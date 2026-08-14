//! Pure, offline-testable port → handler routing for the rendezvous loop
//! (onyums ROADMAP Phase 3 — arbitrary port → handler mapping).
//!
//! Today the built-in handler is HTTP-only: port 443 is served over TLS + axum,
//! port 80 is upgraded to HTTPS (or rejected under strict TLS), and every other
//! port is torn down. This module opens the service up to *any* protocol over an
//! onion service — gRPC, SSH, a game server, Lightning — via a [`StreamHandler`]
//! trait and a [`PortRouter`] that maps a caller-registered port to its handler.
//!
//! The TLS-first stance is preserved: ports 80 and 443 stay reserved for the
//! built-in HTTP handler (the [`Tls`](crate::Tls) decision wins for them), so a
//! raw handler can only occupy one of the *otherwise-rejected* ports. The
//! routing decision itself is pure data — [`PortRouter::dispatch`] — so it is
//! unit-testable with no live Tor network; only the act of serving an accepted
//! stream ([`StreamHandler::serve`]) touches the live path.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tls_policy::{self, PlaintextPolicy, PortAction};

/// An accepted onion-service stream handed to a [`StreamHandler`]: an owned,
/// boxed bidirectional byte stream.
///
/// A single `dyn` object cannot name two non-auto traits (`AsyncRead` *and*
/// `AsyncWrite`), so they are unified behind the [`AsyncStream`] marker trait,
/// which is blanket-implemented for every type that is both (plus `Send + Unpin`
/// so the stream can move across tasks and be polled). The accepted arti onion
/// stream satisfies this, as does an in-memory [`tokio::io::duplex`] pair — which
/// is what lets a [`StreamHandler`] be exercised offline.
pub type OnionStream = Pin<Box<dyn AsyncStream>>;

/// Marker unifying the two halves of a bidirectional stream into one object-safe
/// trait (see [`OnionStream`]). Blanket-implemented; never implemented by hand.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// The future returned by [`StreamHandler::serve`]: owned (`'static`) so the
/// rendezvous loop can drive it on a spawned task, and `Send` so it can move
/// across the multithreaded runtime.
pub type ServeFuture = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

/// What protections a [`StreamHandler`] applies to the streams it serves — the
/// operator-facing summary that keeps the raw-port exposure warning honest.
///
/// A bare raw handler (e.g. [`RawTcpHandler`](crate::RawTcpHandler)) applies none: its
/// stream goes straight to the backend. The wrapper handlers report what they add and
/// merge in whatever they wrap, so a `ConnectionLimit<AuthGate<RawTcpHandler>>` reports
/// *both* a limit and an authorizer. [`PortRouter::exposures`] reads this off each
/// registered handler so `serve()`'s launch warning can say "this raw port is gated by an
/// authorizer" instead of blanket-claiming the whole defence stack is bypassed.
///
/// Non-exhaustive: more protection kinds (a per-port TLS wrapper, say) may be reported in
/// future without a breaking change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandlerProtection {
	/// A concurrency cap is in force, with this maximum (see
	/// [`ConnectionLimit`](crate::ConnectionLimit)).
	pub connection_limit: Option<usize>,
	/// A [`StreamAuthorizer`](crate::StreamAuthorizer) must approve a connection before
	/// the backend sees it (see [`AuthGate`](crate::AuthGate)).
	pub authorized: bool,
}

impl HandlerProtection {
	/// A handler that applies no protections of its own — the default for a bare raw
	/// handler.
	#[must_use]
	pub const fn none() -> Self {
		Self { connection_limit: None, authorized: false }
	}

	/// Whether any protection at all is in force.
	#[must_use]
	pub const fn is_protected(&self) -> bool {
		self.authorized || self.connection_limit.is_some()
	}

	/// A human phrase listing the protections in force, or `None` if there are none —
	/// e.g. `"a stream authorizer; a connection limit of 8"`. Used to annotate the
	/// exposure warning.
	#[must_use]
	pub fn describe(&self) -> Option<String> {
		let mut parts = Vec::new();
		if self.authorized {
			parts.push("a stream authorizer".to_string());
		}
		if let Some(max) = self.connection_limit {
			parts.push(format!("a connection limit of {max}"));
		}
		if parts.is_empty() { None } else { Some(parts.join("; ")) }
	}
}

/// Serves a single accepted stream for a caller-registered port.
///
/// This is the versatility layer that lets onyums tunnel an arbitrary protocol
/// over an onion service — gRPC, SSH, a game server, Lightning — alongside the
/// built-in TLS-enforced HTTP handler.
///
/// A handler is shared across every circuit (held behind an `Arc`), so it must be
/// `Send + Sync`; [`serve`](Self::serve) takes `&self` and returns an owned
/// `'static` future, so an implementation clones whatever per-connection state it
/// needs (a backend address, say) into the future rather than borrowing `self`.
pub trait StreamHandler: Send + Sync {
	/// Serve one accepted onion stream to completion.
	///
	/// `stream` is the already-accepted bidirectional onion stream; the handler
	/// owns it for the connection's lifetime and negotiates its own transport
	/// security (a raw handler is not wrapped in the built-in TLS the HTTP handler
	/// uses).
	fn serve(&self, stream: OnionStream) -> ServeFuture;

	/// What protections this handler applies, for the operator-facing exposure report
	/// ([`PortRouter::exposures`]).
	///
	/// Defaults to [`HandlerProtection::none`] — a bare handler hands its stream straight
	/// to the backend. A wrapper (like [`ConnectionLimit`](crate::ConnectionLimit) or
	/// [`AuthGate`](crate::AuthGate)) overrides this to report what it adds *and* merge in
	/// what it wraps, so nesting composes.
	fn protection(&self) -> HandlerProtection {
		HandlerProtection::none()
	}
}

/// What the rendezvous loop should do with a BEGIN cell for a given port — the
/// pure routing decision, generalizing `PortAction` with the caller-registered
/// raw handlers.
pub enum PortDispatch<'a> {
	/// Serve over the built-in TLS + HTTP handler (the axum app). Port 443.
	ServeHttp,
	/// Answer with a `301` redirect to HTTPS. Port 80 under
	/// `PlaintextPolicy::Upgrade`.
	RedirectToHttps,
	/// Serve with a caller-registered raw [`StreamHandler`].
	Raw(&'a Arc<dyn StreamHandler>),
	/// Reject the stream and tear down the circuit.
	Reject,
}

impl std::fmt::Debug for PortDispatch<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// A `dyn StreamHandler` is not `Debug`; render the variant tag only.
		let tag = match self {
			Self::ServeHttp => "ServeHttp",
			Self::RedirectToHttps => "RedirectToHttps",
			Self::Raw(_) => "Raw",
			Self::Reject => "Reject",
		};
		f.write_str(tag)
	}
}

/// The lowest and highest ports reserved for the built-in TLS-enforced HTTP
/// handler. A raw [`StreamHandler`] may not be registered on either — the
/// TLS-first decision (serve / upgrade / reject) always wins for them.
pub const RESERVED_HTTP_PORTS: [u16; 2] = [80, 443];

/// Whether `port` is one of the `RESERVED_HTTP_PORTS` (80/443) served by the built-in
/// TLS-enforced HTTP handler — the only ports where the Skin HTTP gate can render a
/// challenge page. A raw port has no such surface, so a circuit-policy `Challenge` there
/// must fail closed rather than serve the stream ungated (see
/// [`circuit_gate::stream_disposition`](crate::circuit_gate::stream_disposition)).
#[must_use]
pub const fn is_reserved_http_port(port: u16) -> bool {
	let mut i = 0;
	while i < RESERVED_HTTP_PORTS.len() {
		if RESERVED_HTTP_PORTS[i] == port {
			return true;
		}
		i += 1;
	}
	false
}

/// Maps a port to the handler that serves it: the built-in HTTP handler on the
/// reserved ports 80/443, and caller-registered raw [`StreamHandler`]s on any
/// other (otherwise-rejected) port.
///
/// The TLS-first port decision is delegated to `tls_policy::port_action`, so
/// there is one source of truth for the built-in behaviour; raw handlers only
/// fill the ports that decision would otherwise reject. An empty router
/// reproduces today's HTTP-only behaviour exactly.
#[derive(Clone, Default)]
pub struct PortRouter {
	handlers: HashMap<u16, Arc<dyn StreamHandler>>,
}

/// Ports whose exposure over an onion service warrants naming the service out loud
/// (onyums ROADMAP Phase 2 — raw-port security controls).
///
/// These are the administrative and datastore protocols that are normally bound to
/// loopback or a private network precisely *because* they are not built to face
/// hostile traffic — several authenticate weakly or not at all by default. Publishing
/// one on an onion service is a legitimate thing to do deliberately (that is much of
/// the appeal: a globally reachable admin port with no open firewall port and no IP to
/// scan), and a bad thing to do accidentally. The list exists to tell the two apart in
/// the log.
///
/// Deliberately conservative: only ports with an unambiguous well-known assignment,
/// so the warning stays worth reading. An unlisted port still gets the generic
/// bypass warning — this table only adds the service name.
const SENSITIVE_PORTS: &[(u16, &str)] = &[(22, "SSH"), (23, "Telnet"), (389, "LDAP"), (445, "SMB"), (1433, "Microsoft SQL Server"), (2375, "Docker API (unauthenticated)"), (2376, "Docker API"), (2379, "etcd"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"), (5672, "AMQP / RabbitMQ"), (5900, "VNC"), (6379, "Redis"), (9092, "Kafka"), (9200, "Elasticsearch"), (11211, "Memcached"), (27017, "MongoDB")];

/// The well-known name of a sensitive service on `port`, if it has one
/// (see `SENSITIVE_PORTS`).
///
/// Pure lookup, so it is unit-testable with no live Tor network.
#[must_use]
pub fn well_known_sensitive_service(port: u16) -> Option<&'static str> {
	SENSITIVE_PORTS.iter().find(|(p, _)| *p == port).map(|(_, name)| *name)
}

/// One registered raw port and what serving it gives up
/// (see [`PortRouter::exposures`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPortExposure {
	/// The registered port.
	pub port: u16,
	/// The well-known sensitive service on this port, if any (e.g. `"SSH"` for 22).
	pub service: Option<&'static str>,
	/// What protections the handler on this port applies of its own accord (a connection
	/// limit, a stream authorizer). The HTTP-path defences (Skin/WAF/rate-limit/TLS) still
	/// do not apply regardless — this only reports what the raw handler itself adds back.
	pub protection: HandlerProtection,
}

impl RawPortExposure {
	/// Is this a well-known administrative/datastore port (see `SENSITIVE_PORTS`)?
	#[must_use]
	pub const fn is_sensitive(&self) -> bool {
		self.service.is_some()
	}

	/// The operator-facing warning for this exposure.
	///
	/// States the bypass in terms of what is *not* running, since that is the part a
	/// reader can act on, and names the service when it is a known-sensitive port so the
	/// line is specific rather than boilerplate to scroll past.
	#[must_use]
	pub fn message(&self) -> String {
		let Self { port, service, protection } = *self;
		let bypass = format!("port {port} serves a raw handler: the Skin gate (PoW/challenge), the WAF, rate limiting, and the built-in TLS do NOT apply to it. The onion circuit still encrypts and authenticates the channel; everything above it is the backend protocol's job.");
		let mut message = match service {
			Some(service) => format!("{bypass} Port {port} is the well-known {service} port — if that is deliberate, ensure {service} does its own authentication, since restricted discovery controls who can *find* the service, not who may use it."),
			None => bypass,
		};
		// Report what the handler *does* add back, so the warning does not over-state the
		// exposure of a port that is, say, behind a shared-secret authorizer.
		if let Some(applied) = protection.describe() {
			use std::fmt::Write as _;
			// Writing to a String is infallible.
			let _ = write!(message, " This handler does apply: {applied}.");
		}
		message
	}
}

impl PortRouter {
	/// An empty router — no raw handlers, so dispatch is exactly the built-in
	/// HTTP-only behaviour.
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	/// Register `handler` to serve `port`.
	///
	/// # Errors
	/// Returns an error if `port` is `0`, is one of the `RESERVED_HTTP_PORTS`
	/// (80/443, reserved for the built-in TLS-enforced HTTP handler), or already
	/// has a registered handler.
	pub fn register(&mut self, port: u16, handler: Arc<dyn StreamHandler>) -> Result<()> {
		if port == 0 {
			anyhow::bail!("cannot register a stream handler on port 0");
		}
		if RESERVED_HTTP_PORTS.contains(&port) {
			anyhow::bail!("port {port} is reserved for the built-in HTTP handler (TLS-first); raw handlers must use another port");
		}
		if self.handlers.contains_key(&port) {
			anyhow::bail!("a stream handler is already registered on port {port}");
		}
		self.handlers.insert(port, handler);
		Ok(())
	}

	/// Assemble a router from a builder's `route_port` registrations, surfacing the
	/// first invalid registration (a reserved/zero port, or a duplicate).
	///
	/// The bulk form of [`register`](Self::register): it runs the same per-port
	/// validation, so the whole thing fails offline — before any Tor launch — the moment
	/// a single registration is bad. Backs `OnionServiceBuilder::serve`'s port-router
	/// assembly, and is unit-testable with no live Tor network.
	///
	/// # Errors
	/// Returns the first [`register`](Self::register) error (port `0`, a
	/// `RESERVED_HTTP_PORTS` entry, or a duplicate port).
	pub fn from_registrations(handlers: Vec<(u16, Arc<dyn StreamHandler>)>) -> Result<Self> {
		let mut router = Self::new();
		for (port, handler) in handlers {
			router.register(port, handler)?;
		}
		Ok(router)
	}

	/// What each registered raw port gives up, one [`RawPortExposure`] per port, ordered
	/// by port number (onyums ROADMAP Phase 2 — raw-port security controls).
	///
	/// A raw port is the one hole in onyums' secure-by-default posture, and it is easy to
	/// open without registering what it costs: [`dispatch`](Self::dispatch) hands the
	/// stream straight to the handler, so the Skin gate, the WAF, the rate limiter, and
	/// the built-in TLS — everything on the HTTP path — do not apply. `serve()` logs
	/// these at launch so the decision appears in the operator's log rather than only in
	/// the code that made it.
	///
	/// Pure data derived from the registrations, so it is unit-testable with no live Tor
	/// network. Ordered so the output is deterministic (the backing map is not).
	#[must_use]
	pub fn exposures(&self) -> Vec<RawPortExposure> {
		let mut exposures: Vec<_> = self.handlers.iter().map(|(&port, handler)| RawPortExposure { port, service: well_known_sensitive_service(port), protection: handler.protection() }).collect();
		exposures.sort_unstable_by_key(|e| e.port);
		exposures
	}

	/// Whether any raw handler is registered (an empty router is the HTTP-only
	/// default).
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.handlers.is_empty()
	}

	/// The number of registered raw handlers.
	#[must_use]
	pub fn len(&self) -> usize {
		self.handlers.len()
	}

	/// Whether a raw handler is registered for `port`.
	#[must_use]
	pub fn contains_port(&self, port: u16) -> bool {
		self.handlers.contains_key(&port)
	}

	/// Decide what to do with a stream for `port` under the chosen plaintext
	/// policy.
	///
	/// The built-in TLS-first decision (via `tls_policy::port_action`) wins for
	/// ports 80/443; only a port that decision would *reject* can resolve to a
	/// registered raw handler, falling back to [`PortDispatch::Reject`] when none
	/// is registered.
	#[must_use]
	pub fn dispatch(&self, port: u16, plaintext: PlaintextPolicy) -> PortDispatch<'_> {
		match tls_policy::port_action(port, plaintext) {
			PortAction::ServeTls => PortDispatch::ServeHttp,
			PortAction::RedirectToHttps => PortDispatch::RedirectToHttps,
			PortAction::Reject => self.handlers.get(&port).map_or(PortDispatch::Reject, PortDispatch::Raw),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A handler whose `serve` ignores the stream and succeeds — enough to exercise
	/// registration and routing without a live stream.
	struct NoopHandler;

	impl StreamHandler for NoopHandler {
		fn serve(&self, _stream: OnionStream) -> ServeFuture {
			Box::pin(async { Ok(()) })
		}
	}

	fn handler() -> Arc<dyn StreamHandler> {
		Arc::new(NoopHandler)
	}

	#[test]
	fn empty_router_reproduces_builtin_http_behaviour() {
		let router = PortRouter::new();
		assert!(router.is_empty());
		assert_eq!(router.len(), 0);
		// 443 always serves HTTP over TLS.
		assert!(matches!(router.dispatch(443, PlaintextPolicy::Upgrade), PortDispatch::ServeHttp));
		assert!(matches!(router.dispatch(443, PlaintextPolicy::Reject), PortDispatch::ServeHttp));
		// 80 upgrades or is rejected by the plaintext policy.
		assert!(matches!(router.dispatch(80, PlaintextPolicy::Upgrade), PortDispatch::RedirectToHttps));
		assert!(matches!(router.dispatch(80, PlaintextPolicy::Reject), PortDispatch::Reject));
		// Every other port is rejected with no handler registered.
		for port in [22_u16, 9735, 8080, 65535] {
			assert!(matches!(router.dispatch(port, PlaintextPolicy::Upgrade), PortDispatch::Reject), "port {port}");
		}
	}

	#[test]
	fn registered_handler_serves_an_otherwise_rejected_port() {
		let mut router = PortRouter::new();
		router.register(9735, handler()).expect("9735 is registerable");
		assert!(!router.is_empty());
		assert_eq!(router.len(), 1);
		assert!(router.contains_port(9735));
		// The registered port now routes to the raw handler under either policy
		// (it was rejected before).
		assert!(matches!(router.dispatch(9735, PlaintextPolicy::Upgrade), PortDispatch::Raw(_)));
		assert!(matches!(router.dispatch(9735, PlaintextPolicy::Reject), PortDispatch::Raw(_)));
		// An unregistered port is still rejected.
		assert!(matches!(router.dispatch(22, PlaintextPolicy::Upgrade), PortDispatch::Reject));
	}

	#[test]
	fn reserved_http_ports_cannot_be_registered() {
		let mut router = PortRouter::new();
		for port in RESERVED_HTTP_PORTS {
			let err = router.register(port, handler()).expect_err("reserved port must be rejected");
			assert!(err.to_string().contains("reserved"), "unexpected error for {port}: {err}");
		}
		// The built-in decision still wins for them regardless.
		assert!(matches!(router.dispatch(443, PlaintextPolicy::Upgrade), PortDispatch::ServeHttp));
		assert!(matches!(router.dispatch(80, PlaintextPolicy::Upgrade), PortDispatch::RedirectToHttps));
	}

	#[test]
	fn is_reserved_http_port_matches_only_80_and_443() {
		// The predicate the circuit gate uses to decide whether a Challenge has a surface
		// to render on. Every reserved port reads true; representative raw ports read false.
		for port in RESERVED_HTTP_PORTS {
			assert!(is_reserved_http_port(port), "{port} should be a reserved HTTP port");
		}
		for port in [0u16, 22, 8080, 9000, 65535] {
			assert!(!is_reserved_http_port(port), "{port} must not be a reserved HTTP port");
		}
	}

	#[test]
	fn port_zero_cannot_be_registered() {
		let mut router = PortRouter::new();
		let err = router.register(0, handler()).expect_err("port 0 must be rejected");
		assert!(err.to_string().contains("port 0"), "unexpected error: {err}");
	}

	#[test]
	fn double_registration_is_rejected() {
		let mut router = PortRouter::new();
		router.register(9735, handler()).expect("first registration");
		let err = router.register(9735, handler()).expect_err("second registration must fail");
		assert!(err.to_string().contains("already registered"), "unexpected error: {err}");
		// The first handler is still in place.
		assert_eq!(router.len(), 1);
	}

	#[test]
	fn dispatch_debug_renders_variant_tag() {
		let router = PortRouter::new();
		assert_eq!(format!("{:?}", router.dispatch(443, PlaintextPolicy::Upgrade)), "ServeHttp");
		assert_eq!(format!("{:?}", router.dispatch(80, PlaintextPolicy::Upgrade)), "RedirectToHttps");
		assert_eq!(format!("{:?}", router.dispatch(22, PlaintextPolicy::Upgrade)), "Reject");
		let mut router = router;
		router.register(9735, handler()).expect("register");
		assert_eq!(format!("{:?}", router.dispatch(9735, PlaintextPolicy::Upgrade)), "Raw");
	}

	#[test]
	fn from_registrations_rejects_a_reserved_port() {
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(443, handler())];
		// `PortRouter` is not `Debug` (it holds a `dyn StreamHandler`), so take the
		// error via `.err()` rather than `expect_err`.
		let err = PortRouter::from_registrations(handlers).err().expect("443 is reserved for the built-in HTTP handler");
		assert!(err.to_string().contains("reserved"), "unexpected error: {err}");
	}

	#[test]
	fn from_registrations_registers_valid_non_http_ports() {
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(9735, handler()), (2222, handler())];
		let router = PortRouter::from_registrations(handlers).expect("9735 and 2222 are registerable");
		assert_eq!(router.len(), 2);
		assert!(router.contains_port(9735));
		assert!(router.contains_port(2222));
		// Dispatch routes the registered ports to a raw handler; an unregistered one
		// is still rejected.
		assert!(matches!(router.dispatch(9735, PlaintextPolicy::Upgrade), PortDispatch::Raw(_)));
		assert!(matches!(router.dispatch(8080, PlaintextPolicy::Upgrade), PortDispatch::Reject));
	}

	// ---- Raw-port exposure warnings (Phase 2 — raw-port security controls). ----

	#[test]
	fn an_http_only_service_exposes_nothing() {
		// The default posture registers no raw handler, so there is nothing to warn
		// about and `serve()` stays quiet.
		assert!(PortRouter::new().exposures().is_empty(), "an empty router has no raw exposure");
	}

	#[test]
	fn well_known_sensitive_ports_are_named() {
		assert_eq!(well_known_sensitive_service(22), Some("SSH"));
		assert_eq!(well_known_sensitive_service(5432), Some("PostgreSQL"));
		assert_eq!(well_known_sensitive_service(6379), Some("Redis"));
		assert_eq!(well_known_sensitive_service(27017), Some("MongoDB"));
	}

	#[test]
	fn an_ordinary_port_is_not_flagged_as_a_known_service() {
		// The table is conservative on purpose: a warning that fires "sensitively" on
		// every port would be noise, and noise is scrolled past.
		assert_eq!(well_known_sensitive_service(9735), None, "Lightning's port is not an admin/datastore service");
		assert_eq!(well_known_sensitive_service(8080), None);
		assert_eq!(well_known_sensitive_service(0), None);
	}

	#[test]
	fn no_sensitive_port_collides_with_the_reserved_http_ports() {
		// A sensitive entry on 80/443 would be unreachable: `register` rejects those
		// ports outright, so the warning could never fire and the table would be lying.
		for (port, service) in SENSITIVE_PORTS {
			assert!(!RESERVED_HTTP_PORTS.contains(port), "{service} on reserved port {port} can never be registered");
		}
	}

	#[test]
	fn the_sensitive_table_is_sorted_and_free_of_duplicates() {
		// Sorted is how it stays readable and reviewable as it grows; a duplicate port
		// would make `well_known_sensitive_service` silently prefer the first entry.
		let ports: Vec<u16> = SENSITIVE_PORTS.iter().map(|(p, _)| *p).collect();
		let mut sorted = ports.clone();
		sorted.sort_unstable();
		sorted.dedup();
		assert_eq!(ports, sorted, "SENSITIVE_PORTS must be sorted by port and contain no duplicates");
	}

	#[test]
	fn exposures_are_ordered_by_port_not_by_map_iteration() {
		// The backing map's iteration order is randomised, so without the sort the
		// launch log would shuffle between runs and two runs could not be diffed.
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(9735, handler()), (22, handler()), (5432, handler())];
		let router = PortRouter::from_registrations(handlers).expect("registerable");
		let ports: Vec<u16> = router.exposures().iter().map(|e| e.port).collect();
		assert_eq!(ports, vec![22, 5432, 9735], "exposures must be ordered by port");
	}

	#[test]
	fn every_raw_port_warns_that_the_gate_does_not_apply() {
		// The point of the warning: a raw port bypasses the whole HTTP-path defence
		// stack. That has to be said for an ordinary port too, not only a famous one.
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(9735, handler())];
		let router = PortRouter::from_registrations(handlers).expect("registerable");
		let exposure = router.exposures()[0];
		assert!(!exposure.is_sensitive(), "9735 is not a well-known admin port");
		let message = exposure.message();
		for expected in ["9735", "Skin", "WAF", "rate limiting", "TLS"] {
			assert!(message.contains(expected), "the bypass warning must name {expected}: {message}");
		}
	}

	#[test]
	fn a_sensitive_port_is_named_in_its_warning() {
		// "port 22 serves a raw handler" is easy to skim past; "port 22 is the
		// well-known SSH port" is not. The generic bypass text is still included.
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(22, handler())];
		let router = PortRouter::from_registrations(handlers).expect("registerable");
		let exposure = router.exposures()[0];
		assert!(exposure.is_sensitive());
		assert_eq!(exposure.service, Some("SSH"));
		let message = exposure.message();
		assert!(message.contains("SSH"), "the warning must name the service: {message}");
		assert!(message.contains("Skin"), "the generic bypass warning must still be present: {message}");
	}

	#[test]
	fn exposures_cover_every_registered_port() {
		// A missed port is a silent exposure, which is the exact failure this guards.
		let handlers: Vec<(u16, Arc<dyn StreamHandler>)> = vec![(22, handler()), (2222, handler()), (6379, handler())];
		let router = PortRouter::from_registrations(handlers).expect("registerable");
		assert_eq!(router.exposures().len(), router.len(), "every registered raw port must produce an exposure");
	}

	// ---- Handler protection reporting (Phase 2 — raw-port controls). ----

	/// A handler that reports a fixed protection, so the exposure plumbing can be tested
	/// without pulling in the real wrapper types.
	struct ProtectedHandler(HandlerProtection);
	impl StreamHandler for ProtectedHandler {
		fn serve(&self, _stream: OnionStream) -> ServeFuture {
			Box::pin(async { Ok(()) })
		}

		fn protection(&self) -> HandlerProtection {
			self.0
		}
	}

	#[test]
	fn handler_protection_describes_what_is_in_force() {
		assert!(HandlerProtection::none().describe().is_none(), "no protection describes to nothing");
		assert!(!HandlerProtection::none().is_protected());

		let authed = HandlerProtection { authorized: true, ..HandlerProtection::none() };
		assert!(authed.is_protected());
		assert_eq!(authed.describe().as_deref(), Some("a stream authorizer"));

		let limited = HandlerProtection { connection_limit: Some(4), ..HandlerProtection::none() };
		assert_eq!(limited.describe().as_deref(), Some("a connection limit of 4"));

		let both = HandlerProtection { authorized: true, connection_limit: Some(8) };
		assert_eq!(both.describe().as_deref(), Some("a stream authorizer; a connection limit of 8"));
	}

	#[test]
	fn a_bare_handler_reports_no_protection_and_no_note() {
		let mut router = PortRouter::new();
		router.register(9735, handler()).expect("register");
		let exposure = router.exposures()[0];
		assert!(!exposure.protection.is_protected(), "the default handler adds no protection");
		assert!(!exposure.message().contains("This handler does apply"), "a bare handler gets no protection note: {}", exposure.message());
	}

	#[test]
	fn exposures_report_and_annotate_a_handlers_protections() {
		let mut router = PortRouter::new();
		let protection = HandlerProtection { authorized: true, connection_limit: Some(8) };
		router.register(16379, Arc::new(ProtectedHandler(protection))).expect("register");
		let exposure = router.exposures()[0];
		assert_eq!(exposure.protection, protection, "exposures must carry the handler's reported protection");
		let message = exposure.message();
		// The bypass warning is still present — the HTTP-path defences genuinely do not apply.
		assert!(message.contains("do NOT apply"), "the bypass warning must remain: {message}");
		// But the note now tells the operator what the handler does add back.
		assert!(message.contains("This handler does apply: a stream authorizer; a connection limit of 8"), "the protection note must be present and accurate: {message}");
	}
}
