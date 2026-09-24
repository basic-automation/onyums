#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]
// onyums contains no `unsafe` of its own — forbid it outright (axum/axum-extra advertise
// the same), so any future `unsafe` is a hard compile error, not a silent regression.
#![forbid(unsafe_code)]

//! # Onyums
//! Onyums is a simple axum wrapper for serving tor onion services.
//!
//! # Example
//! ```rust,no_run
//! use onyums::{serve, routing::get, Router};
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, World!" }));
//!
//!     serve(app, "my_onion").await.unwrap();
//! }
//! ```
//! `no_run`: `serve` binds the live Tor network and runs until stopped, so the
//! example is compiled and type-checked but never executed under `cargo test`.

// With the Phase 0 split complete, lib.rs is the crate's front door and nothing else:
// the crate docs above, the module list, and the public surface re-exported from the
// focused modules that implement it. Anything with logic in it belongs in one of them.

pub use axum::*;
pub use onyums_skin::{self, AccountingCircuitPolicy, CircuitPolicy, ClientAuthKey, RestrictedDiscovery, SecurityEvent, SecurityEventSink, Skin};
/// Re-export the arti stack onyums is built on, so downstream crates can depend on the
/// *exact* versions onyums uses without a version skew — the same reason `axum` is
/// re-exported above. If you need arti's `TorClient`, the onion-service config, or the
/// onion key types (e.g. to build a custom [`CircuitPolicy`] or an authorized-clients
/// allowlist from raw keys), reach them through `onyums::arti_client` / `onyums::tor_*`
/// rather than adding your own `arti-client` / `tor-*` dependency.
pub use {arti_client, tor_cell, tor_cert, tor_hscrypto, tor_hsservice, tor_llcrypto, tor_proto, tor_rtcompat};

mod address;
mod builder;
mod circuit_gate;
mod client_auth;
mod connection;
mod connection_limit;
mod handle;
mod http_stack;
pub mod keystore_perms;
mod metrics;
mod port_router;
mod provided_cert;
mod raw_tcp;
mod serve_loop;
mod service_config;
mod status;
mod stream_auth;
mod tls_policy;
mod tls_setup;
mod tor_client;
mod vanity;

pub use address::OnionAddress;
pub use builder::{OnionService, OnionServiceBuilder, serve};
pub use client_auth::{ClientAuthKeypair, ClientAuthKeypairError, provision_client};
pub use connection::ConnectionInfo;
pub use connection_limit::ConnectionLimit;
pub use handle::OnionServiceHandle;
pub use metrics::{ServiceMetrics, fleet_prometheus};
pub use port_router::{AsyncStream, HandlerProtection, OnionStream, PortDispatch, PortRouter, RawPortExposure, ServeFuture, StreamHandler, well_known_sensitive_service};
pub use provided_cert::ProvidedCert;
pub use raw_tcp::RawTcpHandler;
pub use status::{ServiceHealth, ServiceProblem, ServiceProblemKind, ServiceStatus};
pub use stream_auth::{AuthFuture, AuthGate, AuthOutcome, SharedSecretAuth, StreamAuthorizer};
pub use tls_policy::Tls;
pub use tor_client::OnionTorClient;
pub use vanity::{VanityKey, address_from_expanded_secret, address_from_secret_seed, address_from_tor_secret_key_file, expanded_secret_from_tor_file, mine, mine_parallel, mine_within, tor_secret_key_file_from_expanded, validate_prefix};

#[cfg(test)]
mod tests {
	// lib.rs itself is now just the crate's front door, so these imports exist only for
	// the live-Tor test below: it drives the whole stack (bootstrap a second client,
	// dial the service, fetch over a real rendezvous circuit), which is the one thing
	// that cannot belong to any single module.
	use anyhow::Result;
	use arti_client::TorClient;
	use axum::{Router, routing::get};
	use tokio_rustls::rustls;
	use tor_rtcompat::tokio::TokioRustlsRuntime;
	use tracing::{Level, event};

	use super::*;
	use crate::tor_client::{OnionTorClient, storage_dirs};

	#[test]
	fn arti_stack_is_reexported() {
		// Compile-time proof that the arti stack is reachable through onyums, so a
		// downstream needn't add its own version-skew-prone arti dependency. If any
		// re-export path breaks, this stops compiling.
		type _Client = crate::arti_client::TorClient<crate::tor_rtcompat::tokio::TokioRustlsRuntime>;
		// The alias is transparent: it must stay *equal* to the spelled-out type, not
		// merely resemble it, or a caller who mixes the two would stop compiling. The
		// spelled-out runtime is the rustls one on purpose — this line is also what
		// pins that arti runs on rustls (no `openssl-sys` in the tree; deny.toml bans it
		// outright), so a drift back to `TokioNativeTlsRuntime` fails to compile here.
		const fn _alias_is_the_same_type(c: crate::OnionTorClient) -> crate::arti_client::TorClient<crate::tor_rtcompat::tokio::TokioRustlsRuntime> {
			c
		}
		type _Key = crate::tor_hscrypto::pk::HsClientDescEncKey;
		type _Cfg = crate::tor_hsservice::config::OnionServiceConfigBuilder;
		type _Cell = crate::tor_cell::relaycell::msg::End;
	}

	/// Accepts any server certificate. Live-tier only: the service presents a
	/// self-signed certificate for its onion host (the onion address itself
	/// authenticates the service — see the README's TLS discussion), so `WebPKI`
	/// verification is not the subject under test; the served payload is.
	#[derive(Debug)]
	struct AcceptAnyServerCert;

	impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
		fn verify_server_cert(&self, _end_entity: &rustls::pki_types::CertificateDer<'_>, _intermediates: &[rustls::pki_types::CertificateDer<'_>], _server_name: &rustls::pki_types::ServerName<'_>, _ocsp_response: &[u8], _now: rustls::pki_types::UnixTime) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
			Ok(rustls::client::danger::ServerCertVerified::assertion())
		}

		fn verify_tls12_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
			Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
		}

		fn verify_tls13_signature(&self, _message: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
			Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
		}

		fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
			rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
		}
	}

	/// One HTTPS `GET /` against `address` over `client`: rendezvous circuit → TLS
	/// handshake (self-signed accepted) → HTTP/1.1 request → full response text.
	async fn live_fetch_once(client: &OnionTorClient, address: &OnionAddress) -> Result<String> {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let stream = client.connect((address.host(), 443)).await.map_err(|e| anyhow::anyhow!("rendezvous connect failed: {e}"))?;

		let tls_config = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServerCert)).with_no_client_auth();
		let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
		let server_name = rustls::pki_types::ServerName::try_from(address.host().to_string())?;
		let mut tls = connector.connect(server_name, stream).await?;

		tls.write_all(format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", address.host()).as_bytes()).await?;
		// Arti's DataStream transmits a partially-filled Tor cell only on flush; a
		// request smaller than one cell never leaves the client without this. (Live
		// run without it: server-side TLS accept + hyper start, then a client-side
		// stall — the GET sat in the write buffer until the attempt timed out.)
		tls.flush().await?;
		let mut response = Vec::new();
		// `Connection: close` ends the exchange; tolerate a missing TLS close_notify
		// (we assert on the payload, and a truncation that ate it fails the assert).
		let _ = tls.read_to_end(&mut response).await;
		Ok(String::from_utf8_lossy(&response).into_owned())
	}

	/// Which phase the live test is in, readable from outside the runtime. The
	/// watchdog thread prints it on a wall-clock breach, so a wedged run names
	/// *where* it wedged instead of dying silently — the diagnostic the 2026-07-20
	/// hang never produced.
	#[derive(Clone)]
	struct PhaseTracker(std::sync::Arc<std::sync::Mutex<&'static str>>);

	impl PhaseTracker {
		fn new(initial: &'static str) -> Self {
			Self(std::sync::Arc::new(std::sync::Mutex::new(initial)))
		}

		fn set(&self, phase: &'static str) {
			*self.0.lock().expect("phase mutex poisoned") = phase;
		}

		fn get(&self) -> &'static str {
			*self.0.lock().expect("phase mutex poisoned")
		}
	}

	/// A hard wall-clock deadline enforced from a plain `std` thread — deliberately
	/// outside tokio, because the two hang mechanisms it exists to catch both defeat
	/// in-runtime timers: a future that blocks inside `poll` never yields to
	/// `tokio::time::timeout`, and a panic already thrown by such a timeout can wedge
	/// in runtime teardown *after* the async world is gone. Disarms when dropped;
	/// fires `on_breach` with the current phase otherwise.
	struct Watchdog {
		disarm: Option<std::sync::mpsc::Sender<()>>,
		thread: Option<std::thread::JoinHandle<()>>,
	}

	impl Watchdog {
		fn arm(budget: std::time::Duration, phase: PhaseTracker, on_breach: impl FnOnce(&'static str) + Send + 'static) -> Self {
			let (disarm, watch) = std::sync::mpsc::channel::<()>();
			let thread = std::thread::spawn(move || match watch.recv_timeout(budget) {
				// A send *or* a dropped sender both mean the guarded work finished.
				Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {}
				Err(std::sync::mpsc::RecvTimeoutError::Timeout) => on_breach(phase.get()),
			});
			Self { disarm: Some(disarm), thread: Some(thread) }
		}
	}

	impl Drop for Watchdog {
		fn drop(&mut self) {
			// Dropping the sender disconnects the channel, which wakes the watchdog
			// thread immediately; the join is then prompt and keeps the thread from
			// outliving the test that armed it.
			drop(self.disarm.take());
			if let Some(thread) = self.thread.take() {
				let _ = thread.join();
			}
		}
	}

	#[test]
	fn watchdog_disarmed_before_deadline_never_fires() {
		let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
		let phase = PhaseTracker::new("armed");
		let watchdog = Watchdog::arm(std::time::Duration::from_millis(40), phase, {
			let fired = std::sync::Arc::clone(&fired);
			move |_| fired.store(true, std::sync::atomic::Ordering::SeqCst)
		});
		drop(watchdog);
		// Wait well past the deadline: a disarm that merely delayed the breach
		// instead of cancelling it would still trip this.
		std::thread::sleep(std::time::Duration::from_millis(120));
		assert!(!fired.load(std::sync::atomic::Ordering::SeqCst), "a disarmed watchdog must never fire");
	}

	#[test]
	fn watchdog_breach_fires_and_names_the_current_phase() {
		let (report, reported) = std::sync::mpsc::channel::<&'static str>();
		let phase = PhaseTracker::new("initial");
		let watchdog = Watchdog::arm(std::time::Duration::from_millis(40), phase.clone(), move |stuck| {
			let _ = report.send(stuck);
		});
		// The phase set *after* arming must be the one reported — the watchdog reads
		// the tracker at breach time, not a snapshot from when it was armed.
		phase.set("Tor bootstrap");
		let stuck = reported.recv_timeout(std::time::Duration::from_secs(5)).expect("watchdog should fire once its budget elapses");
		assert_eq!(stuck, "Tor bootstrap");
		drop(watchdog);
	}

	/// The live-Tor test tier (onyums ROADMAP: "Add live Tor integration tests …
	/// an `--ignored` or CI-gated live test tier"). Ignored by default because it
	/// bootstraps real Tor clients and publishes a real descriptor — minutes of
	/// wall clock and network egress. Run it explicitly:
	///
	/// ```text
	/// cargo test --lib tests::live_service_serves_over_the_tor_network_and_shuts_down -- --exact --ignored --nocapture
	/// ```
	///
	/// The pass signal is an end-to-end fetch — a second Tor client (the serving
	/// client's config rejects `.onion` dialing) rendezvouses with the service and
	/// must get the app's body back through the full live path: rendezvous circuit →
	/// TLS → hyper → axum. Reachability via [`OnionServiceHandle::ready_timeout`] is
	/// observed but deliberately NOT asserted: arti 0.43 reports `Running` only once
	/// descriptors are uploaded to BOTH `HsDir` rings (current + secondary time
	/// period), and the secondary ring lags minutes behind de-facto reachability (a
	/// live run settled at `Bootstrapping` for 5+ minutes while the primary-ring
	/// descriptor — the one clients use — was published within seconds).
	///
	/// Replaces the old `test_serve`, which could neither fail nor finish: it drove
	/// the blocking [`serve`] wrapper (which runs until the service stops — and
	/// nothing ever stopped it, so a successful launch hung the default suite
	/// indefinitely), and it swallowed every launch error into a DEBUG log, so a
	/// broken launch still passed.
	///
	/// # Why this is a `#[test]` with an explicit runtime, not a `#[tokio::test]`
	///
	/// On 2026-07-20 this test wedged for 70 minutes despite every phase carrying a
	/// `tokio::time::timeout` summing to ~21 — and the launch timeout's panic never
	/// surfaced. Two mechanisms produce exactly that symptom, and this shape closes
	/// both rather than betting on a diagnosis:
	///
	/// 1. **Unbounded runtime teardown.** `#[tokio::test]` drops its runtime when the
	///    body finishes *or panics*, and `Runtime::drop` waits forever for in-flight
	///    `spawn_blocking` tasks — which arti uses. A fired timeout's panic is then
	///    held captured by libtest while the drop never returns, so the run hangs
	///    *with its failure message already thrown*. Here the runtime is explicit:
	///    the body's panic is caught, [`tokio::runtime::Runtime::shutdown_timeout`]
	///    bounds teardown and abandons wedged blocking tasks, and the panic is
	///    re-raised *after* — so a fired timeout reports as the failure it is.
	/// 2. **A future that blocks inside `poll`.** `Timeout` only acts at yield
	///    points; a poll that never returns starves it. No in-runtime construct can
	///    catch that, so a [`Watchdog`] on a plain `std` thread enforces the
	///    whole-test wall-clock ceiling and aborts the process, naming the stuck
	///    phase. An abort is deliberate: this tier runs alone (`--exact --ignored`),
	///    and a loud bounded death beats a silent infinite hang.
	#[test]
	#[ignore = "bootstraps against the live Tor network; run explicitly with --ignored"]
	fn live_service_serves_over_the_tor_network_and_shuts_down() {
		let phase = PhaseTracker::new("building the tokio runtime");
		// Ceiling = the sum of the body's own phase timeouts (5 launch + 1 ready +
		// 5 fetch bootstrap + 8 × ~1.25 fetch ≈ 21) plus shutdown + teardown slack.
		// If this fires, some phase overran its own bound — the 2026-07-20 defect.
		let _watchdog = Watchdog::arm(std::time::Duration::from_mins(25), phase.clone(), |stuck| {
			eprintln!("live tier watchdog: the 25-minute wall-clock ceiling elapsed while in phase \"{stuck}\" — a per-phase timeout failed to fire or teardown wedged; aborting so the run dies loudly instead of hanging");
			std::process::abort();
		});

		let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("multi-thread tokio runtime should build");
		let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(live_test_body(&phase))));

		// Bounded teardown — the half a `#[tokio::test]` cannot do. A minute is
		// generous for arti's background tasks; whatever is still wedged after that
		// is abandoned rather than waited on forever.
		phase.set("runtime teardown");
		runtime.shutdown_timeout(std::time::Duration::from_mins(1));

		if let Err(panic) = body {
			std::panic::resume_unwind(panic);
		}
	}

	async fn live_test_body(phase: &PhaseTracker) {
		// Best-effort logging for interactive debugging: `try_init` cannot panic on a
		// subscriber some other test already installed.
		let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

		let app = Router::new().route("/", get(|| async { "Hello, World!" }));

		// Ephemeral: a throwaway identity under the OS temp tree (removed on handle
		// drop), so live runs never write into the persistent ./tor/onyums keystore.
		// `no_skin`: the abuse gate answers an uncleared first request with a
		// challenge, not the app body; the gate has its own offline tests — this tier
		// verifies the live transport.
		let launch = OnionService::builder().router(app).nickname("onyums-live-test").ephemeral().no_skin().serve();

		// Bound the launch — bootstrap is unbounded on a blocked network — so this
		// tier fails in minutes rather than hanging the way its predecessor did.
		phase.set("Tor bootstrap + service launch");
		let handle = tokio::time::timeout(std::time::Duration::from_mins(5), launch).await.expect("Tor bootstrap + service launch should finish within 5 minutes").expect("live launch should yield a service handle");

		// The minted address must be a valid v3 onion address, not just non-empty.
		OnionAddress::parse(handle.onion_address().as_str()).expect("launched service must expose a valid v3 onion address");

		// Soft signal only (see the doc comment): give full reachability a short
		// window and record the outcome, but do not fail on arti's conservative
		// both-rings readiness.
		phase.set("readiness observation");
		let ready = handle.ready_timeout(std::time::Duration::from_mins(1)).await;
		event!(Level::INFO, "live tier: ready_timeout(60s) = {ready}, status = {:?}", handle.status());

		// A second client that is allowed to dial `.onion` addresses. It shares the
		// disposable network cache (no second consensus download) but gets its own
		// throwaway state dir, cleaned up below.
		phase.set("fetch-client bootstrap");
		let (fetch_state, fetch_cache) = storage_dirs(true);
		let mut fetch_cfg = arti_client::config::TorClientConfigBuilder::from_directories(&fetch_state, &fetch_cache);
		fetch_cfg.address_filter().allow_onion_addrs(true);
		let fetch_cfg = fetch_cfg.build().expect("fetch-client config should build");
		// The service launch above already installed rustls' provider for arti; this
		// second client is built directly rather than through `setup_tor_client`, so
		// say so explicitly instead of depending on the launch having run first.
		let _ = crate::tor_client::install_crypto_provider();
		let runtime = TokioRustlsRuntime::current().expect("current tokio runtime");
		let fetch_client = tokio::time::timeout(std::time::Duration::from_mins(5), TorClient::with_runtime(runtime).config(fetch_cfg).create_bootstrapped()).await.expect("fetch-client bootstrap should finish within 5 minutes").expect("fetch client should bootstrap");

		// The authoritative live signal: the app's body comes back through a real
		// rendezvous. Retry across HsDir propagation lag right after first publish.
		phase.set("live fetch attempts");
		let mut served_body = None;
		for attempt in 1..=8 {
			match tokio::time::timeout(std::time::Duration::from_mins(1), live_fetch_once(&fetch_client, handle.onion_address())).await {
				Ok(Ok(response)) if response.contains("Hello, World!") => {
					event!(Level::INFO, "live tier: fetch attempt {attempt} served the app body");
					served_body = Some(response);
					break;
				}
				Ok(Ok(response)) => event!(Level::INFO, "live tier: fetch attempt {attempt} got an unexpected response: {response:?}"),
				Ok(Err(err)) => event!(Level::INFO, "live tier: fetch attempt {attempt} failed: {err:#}"),
				Err(_) => event!(Level::INFO, "live tier: fetch attempt {attempt} timed out"),
			}
			tokio::time::sleep(std::time::Duration::from_secs(15)).await;
		}
		drop(fetch_client);
		crate::tor_client::remove_ephemeral_state_dir(std::path::Path::new(&fetch_state));

		let response = served_body.expect("no fetch attempt got the app body back over the live Tor network");
		assert!(response.starts_with("HTTP/1.1 200"), "expected a 200 response, got: {}", response.lines().next().unwrap_or(""));

		// Graceful teardown must return — the missing half of the old test. Bounded
		// like every other phase, so a wedged accept loop fails the run instead of
		// hanging it.
		phase.set("graceful shutdown");
		tokio::time::timeout(std::time::Duration::from_mins(1), handle.shutdown()).await.expect("graceful shutdown should complete within 60 seconds");
	}
}
