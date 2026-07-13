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
}

/// What the rendezvous loop should do with a BEGIN cell for a given port — the
/// pure routing decision, generalizing [`PortAction`] with the caller-registered
/// raw handlers.
pub enum PortDispatch<'a> {
	/// Serve over the built-in TLS + HTTP handler (the axum app). Port 443.
	ServeHttp,
	/// Answer with a `301` redirect to HTTPS. Port 80 under
	/// [`PlaintextPolicy::Upgrade`].
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

/// Whether `port` is one of the [`RESERVED_HTTP_PORTS`] (80/443) served by the built-in
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
/// The TLS-first port decision is delegated to [`tls_policy::port_action`], so
/// there is one source of truth for the built-in behaviour; raw handlers only
/// fill the ports that decision would otherwise reject. An empty router
/// reproduces today's HTTP-only behaviour exactly.
#[derive(Clone, Default)]
pub struct PortRouter {
	handlers: HashMap<u16, Arc<dyn StreamHandler>>,
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
	/// Returns an error if `port` is `0`, is one of the [`RESERVED_HTTP_PORTS`]
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
	/// [`RESERVED_HTTP_PORTS`] entry, or a duplicate port).
	pub fn from_registrations(handlers: Vec<(u16, Arc<dyn StreamHandler>)>) -> Result<Self> {
		let mut router = Self::new();
		for (port, handler) in handlers {
			router.register(port, handler)?;
		}
		Ok(router)
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
	/// The built-in TLS-first decision (via [`tls_policy::port_action`]) wins for
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
}
