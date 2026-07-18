//! A per-port authorization hook for a raw port (onyums ROADMAP Phase 2 — raw-port
//! security controls).
//!
//! [`AuthGate`] wraps any [`StreamHandler`] with a [`StreamAuthorizer`] that must approve
//! an accepted stream *before the backend sees it*. It is the authentication half of the
//! raw-port story whose concurrency half is
//! [`ConnectionLimit`](crate::ConnectionLimit): a raw port bypasses the Skin gate, the
//! WAF, and the rate limiter entirely (see
//! [`PortRouter::exposures`](crate::PortRouter::exposures)), so the only thing standing
//! between a rendezvous circuit and, say, an unauthenticated Redis or Docker socket is
//! whatever the backend protocol does for itself — which for the ports named in
//! `SENSITIVE_PORTS` is often nothing. An `AuthGate` puts a decision in front of it.
//!
//! ```rust
//! use onyums::{AuthFuture, AuthGate, AuthOutcome, OnionStream, RawTcpHandler, StreamAuthorizer};
//!
//! // A toy authorizer that admits every stream unchanged. Real ones read a preamble
//! // (see `SharedSecretAuth`) or consult external state; the shape is the same.
//! struct AdmitAll;
//! impl StreamAuthorizer for AdmitAll {
//!     fn authorize(&self, stream: OnionStream) -> AuthFuture {
//!         Box::pin(async move { Ok(AuthOutcome::Admit(stream)) })
//!     }
//! }
//!
//! let gate = AuthGate::new(RawTcpHandler::new("127.0.0.1:6379"), AdmitAll);
//! # let _ = gate;
//! ```
//!
//! **Fail closed.** A [`Refuse`](AuthOutcome::Refuse) verdict — *and* an authorizer that
//! returns an error — closes the stream without touching the backend. An authorizer is a
//! gate, so the safe default when it cannot make up its mind is to deny, never to let the
//! stream through ungated.

use std::sync::Arc;

use anyhow::{Result, bail};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tracing::{Level, event};

use crate::port_router::{HandlerProtection, OnionStream, ServeFuture, StreamHandler};

/// The future returned by [`StreamAuthorizer::authorize`]: owned (`'static`) and `Send`,
/// so it can be driven on the spawned per-connection task like a [`ServeFuture`].
pub type AuthFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<AuthOutcome>> + Send + 'static>>;

/// The verdict a [`StreamAuthorizer`] returns for one accepted raw stream.
pub enum AuthOutcome {
	/// Admit the connection: hand this stream to the backend.
	///
	/// An authorizer that read a preamble to make its decision returns the *advanced*
	/// stream here, so the backend sees only the bytes that follow the preamble the
	/// authorizer consumed (this is how [`SharedSecretAuth`](crate::SharedSecretAuth)
	/// strips its token). An authorizer that read nothing returns the stream untouched.
	Admit(OnionStream),
	/// Refuse the connection: the backend never sees the stream, and it is closed.
	Refuse,
}

/// Decides whether an accepted raw stream may reach the backend, *before* it does.
///
/// The authorizing counterpart to [`StreamHandler`]: where a handler serves a stream, an
/// authorizer gates one. It is shared across every circuit (held behind an `Arc`), so it
/// must be `Send + Sync`; [`authorize`](Self::authorize) takes `&self` and returns an
/// owned `'static` future, so an implementation clones whatever per-connection state it
/// needs into the future rather than borrowing `self`.
///
/// An authorizer *may* read from the stream (for example, a fixed-length preamble token)
/// to make its decision. Any bytes it reads are consumed: on [`Admit`](AuthOutcome::Admit)
/// it returns the advanced stream, and the backend sees only what follows.
pub trait StreamAuthorizer: Send + Sync {
	/// Inspect one accepted onion stream and decide whether the backend may serve it.
	///
	/// # Errors
	/// An `Err` is treated exactly like [`AuthOutcome::Refuse`] by [`AuthGate`] — the
	/// backend never sees the stream — but it carries a cause for the operator's log. Use
	/// it for "could not decide" (an I/O error reading a preamble), and `Ok(Refuse)` for a
	/// clean, expected rejection (a bad token).
	fn authorize(&self, stream: OnionStream) -> AuthFuture;
}

/// Gates a raw port behind a [`StreamAuthorizer`], refusing a stream the authorizer does
/// not approve.
///
/// Wraps any [`StreamHandler`] — including [`RawTcpHandler`](crate::RawTcpHandler), and it
/// composes with [`ConnectionLimit`](crate::ConnectionLimit) in either order — and is
/// itself a `StreamHandler`, so it drops straight into
/// [`route_port`](crate::OnionServiceBuilder::route_port):
///
/// ```rust,no_run
/// # use onyums::{AuthFuture, AuthGate, AuthOutcome, ConnectionLimit, OnionService, OnionStream, RawTcpHandler, StreamAuthorizer, routing::get, Router};
/// # struct MyAuth;
/// # impl StreamAuthorizer for MyAuth {
/// #     fn authorize(&self, stream: OnionStream) -> AuthFuture { Box::pin(async move { Ok(AuthOutcome::Admit(stream)) }) }
/// # }
/// # fn f() -> anyhow::Result<()> {
/// // Authorize first, then cap concurrency on what the authorizer admitted.
/// let redis = ConnectionLimit::new(AuthGate::new(RawTcpHandler::new("127.0.0.1:6379"), MyAuth), 8)?;
/// let builder = OnionService::builder()
///     .router(Router::new().route("/", get(|| async { "hi" })))
///     .nickname("my_onion")
///     .route_port(16379, redis);
/// # Ok(())
/// # }
/// ```
pub struct AuthGate<H> {
	inner: Arc<H>,
	authorizer: Arc<dyn StreamAuthorizer>,
}

impl<H> AuthGate<H> {
	/// Gate `inner` behind `authorizer`: every accepted stream must be
	/// [`Admit`](AuthOutcome::Admit)ted before `inner` serves it.
	pub fn new<A: StreamAuthorizer + 'static>(inner: H, authorizer: A) -> Self {
		Self { inner: Arc::new(inner), authorizer: Arc::new(authorizer) }
	}
}

impl<H: StreamHandler + 'static> StreamHandler for AuthGate<H> {
	fn serve(&self, stream: OnionStream) -> ServeFuture {
		let inner = Arc::clone(&self.inner);
		let authorizer = Arc::clone(&self.authorizer);
		Box::pin(async move {
			match authorizer.authorize(stream).await {
				Ok(AuthOutcome::Admit(stream)) => inner.serve(stream).await,
				Ok(AuthOutcome::Refuse) => {
					// A clean, expected rejection. The stream was dropped by the authorizer
					// (it took ownership and did not hand it back), which closes it.
					event!(Level::WARN, "Refused a raw-port connection: the stream authorizer rejected it before the backend.");
					bail!("stream authorizer refused the connection");
				}
				Err(err) => {
					// An authorizer that errored fails closed — the backend never sees the
					// stream — but the cause is carried for the operator's log.
					event!(Level::WARN, "Refused a raw-port connection: the stream authorizer errored: {err:#}");
					Err(err.context("stream authorizer failed; refusing the connection"))
				}
			}
		})
	}

	fn protection(&self) -> HandlerProtection {
		// Report that a stream is authorized before the backend, merging in whatever the
		// wrapped handler already protects.
		let mut protection = self.inner.protection();
		protection.authorized = true;
		protection
	}
}

/// A [`StreamAuthorizer`] that admits a stream only if it opens with a shared secret.
///
/// The batteries-included authorizer: the client prepends the pre-shared secret bytes to
/// the connection, the gate reads exactly that many bytes, compares them to the configured
/// secret in constant time, and on a match hands the *rest* of the stream to the backend
/// (the secret is stripped — the backend never sees it). This is how you put an
/// authentication step in front of a raw backend that has none of its own — a Redis, a
/// Docker socket, a Memcached — reachable only to a client that holds the secret.
///
/// ```rust
/// use onyums::{AuthGate, RawTcpHandler, SharedSecretAuth};
///
/// # fn f() -> anyhow::Result<()> {
/// let auth = SharedSecretAuth::new(b"correct horse battery staple".to_vec())?;
/// let redis = AuthGate::new(RawTcpHandler::new("127.0.0.1:6379"), auth);
/// // .route_port(16379, redis)
/// # let _ = redis;
/// # Ok(())
/// # }
/// ```
///
/// **What it is and is not.** It is a bearer credential shared by every authorized client
/// — the same shape as a restricted-discovery key, and with the same caveats (see the
/// README's restricted-discovery limits): a leaked secret is a breach, there are no
/// per-client identities or roles, and removing access means rotating the secret for
/// everyone. It authenticates *the channel*, not a user; layer real per-user auth in the
/// backend on top. It is deliberately a raw byte prefix, not a challenge/response, so it
/// adds no round trip over the Tor latency budget — which means it does **not** defend
/// against replay by an attacker who already captured the preamble (the onion circuit is
/// encrypted end-to-end, so that requires compromising an endpoint, but say so plainly).
/// The comparison is constant-time so a wrong secret cannot be recovered byte-by-byte from
/// timing; the *length* of the secret is still observable from how many bytes are read.
pub struct SharedSecretAuth {
	secret: Arc<[u8]>,
}

impl SharedSecretAuth {
	/// Build an authorizer that admits a stream opening with exactly `secret`.
	///
	/// # Errors
	/// Returns an error if `secret` is empty: an empty preamble is read as zero bytes and
	/// matches unconditionally, which would admit every stream — a gate that is silently no
	/// gate. Rejected here, offline, rather than in production.
	pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self> {
		let secret = secret.into();
		if secret.is_empty() {
			bail!("a shared secret must not be empty; an empty preamble would admit every connection");
		}
		Ok(Self { secret: secret.into() })
	}

	/// The number of preamble bytes this authorizer reads (the secret's length).
	#[must_use]
	pub fn preamble_len(&self) -> usize {
		self.secret.len()
	}
}

impl StreamAuthorizer for SharedSecretAuth {
	fn authorize(&self, mut stream: OnionStream) -> AuthFuture {
		let secret = Arc::clone(&self.secret);
		Box::pin(async move {
			let mut preamble = vec![0u8; secret.len()];
			// A short read (the peer closed before sending the whole preamble) is a failure
			// to decide, not a clean rejection: it surfaces as an `Err`, which `AuthGate`
			// fails closed on. Constant-time compare below only runs on a full-length read.
			stream.read_exact(&mut preamble).await.map_err(|e| anyhow::anyhow!("could not read the {}-byte auth preamble: {e}", secret.len()))?;
			if preamble.ct_eq(&secret).into() {
				// The secret is consumed; the backend sees only what follows it.
				Ok(AuthOutcome::Admit(stream))
			} else {
				Ok(AuthOutcome::Refuse)
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	/// A backend that records whether it was ever reached and echoes back one byte, so a
	/// test can prove both that admit reaches it and that refuse does not.
	struct RecordingBackend {
		served: Arc<AtomicUsize>,
	}

	impl StreamHandler for RecordingBackend {
		fn serve(&self, mut stream: OnionStream) -> ServeFuture {
			let served = Arc::clone(&self.served);
			Box::pin(async move {
				served.fetch_add(1, Ordering::SeqCst);
				// Read whatever the authorizer left for us and echo it, so a test can assert
				// on exactly the bytes the backend received (i.e. that a preamble was stripped).
				let mut buf = Vec::new();
				let _ = stream.read_to_end(&mut buf).await;
				stream.write_all(&buf).await.ok();
				stream.flush().await.ok();
				Ok(())
			})
		}
	}

	fn backend() -> (RecordingBackend, Arc<AtomicUsize>) {
		let served = Arc::new(AtomicUsize::new(0));
		(RecordingBackend { served: Arc::clone(&served) }, served)
	}

	/// A duplex pair standing in for an accepted onion stream: the gate gets one half, the
	/// test drives the other. No Tor.
	fn pipe() -> (OnionStream, tokio::io::DuplexStream) {
		let (gate_side, test_side) = tokio::io::duplex(256);
		(Box::pin(gate_side), test_side)
	}

	/// An authorizer that admits every stream unchanged.
	struct AdmitAll;
	impl StreamAuthorizer for AdmitAll {
		fn authorize(&self, stream: OnionStream) -> AuthFuture {
			Box::pin(async move { Ok(AuthOutcome::Admit(stream)) })
		}
	}

	/// An authorizer that refuses every stream (dropping it).
	struct RefuseAll;
	impl StreamAuthorizer for RefuseAll {
		fn authorize(&self, _stream: OnionStream) -> AuthFuture {
			Box::pin(async move { Ok(AuthOutcome::Refuse) })
		}
	}

	#[tokio::test]
	async fn an_admitted_stream_reaches_the_backend() {
		let (backend, served) = backend();
		let gate = AuthGate::new(backend, AdmitAll);
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		test_side.write_all(b"ping").await.expect("write");
		test_side.shutdown().await.expect("shutdown");
		let mut echoed = Vec::new();
		test_side.read_to_end(&mut echoed).await.expect("read echo");

		serve.await.expect("task").expect("an admitted connection serves");
		assert_eq!(served.load(Ordering::SeqCst), 1, "the backend must serve an admitted stream");
		assert_eq!(echoed, b"ping", "the backend must receive exactly what the client sent");
	}

	#[tokio::test]
	async fn a_refused_stream_never_reaches_the_backend() {
		let (backend, served) = backend();
		let gate = AuthGate::new(backend, RefuseAll);
		let (stream, _test_side) = pipe();

		let err = gate.serve(stream).await.expect_err("a refused connection is an error the loop can log");
		assert!(err.to_string().contains("refused"), "unexpected error: {err}");
		assert_eq!(served.load(Ordering::SeqCst), 0, "the backend must never see a refused stream");
	}

	#[tokio::test]
	async fn an_authorizer_that_errors_fails_closed() {
		// "Could not decide" must deny, not admit — otherwise a transient read error on the
		// preamble would open the backend to an unauthenticated stream.
		struct Errs;
		impl StreamAuthorizer for Errs {
			fn authorize(&self, _stream: OnionStream) -> AuthFuture {
				Box::pin(async move { anyhow::bail!("preamble read failed") })
			}
		}

		let (backend, served) = backend();
		let gate = AuthGate::new(backend, Errs);
		let (stream, _test_side) = pipe();

		let err = gate.serve(stream).await.expect_err("an authorizer error must refuse");
		assert!(err.to_string().contains("refusing the connection"), "the refusal context must be present: {err}");
		assert!(format!("{err:#}").contains("preamble read failed"), "the underlying cause must be carried: {err:#}");
		assert_eq!(served.load(Ordering::SeqCst), 0, "an authorizer error must not reach the backend");
	}

	#[tokio::test]
	async fn an_authorizer_can_strip_a_preamble_before_the_backend() {
		// The load-bearing capability: an authorizer reads a preamble to decide, and the
		// backend sees only what follows. This is exactly what SharedSecretAuth does.
		struct StripFourBytes;
		impl StreamAuthorizer for StripFourBytes {
			fn authorize(&self, mut stream: OnionStream) -> AuthFuture {
				Box::pin(async move {
					let mut tag = [0u8; 4];
					stream.read_exact(&mut tag).await?;
					if &tag == b"open" { Ok(AuthOutcome::Admit(stream)) } else { Ok(AuthOutcome::Refuse) }
				})
			}
		}

		let (backend, served) = backend();
		let gate = AuthGate::new(backend, StripFourBytes);
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		test_side.write_all(b"openpayload").await.expect("write");
		test_side.shutdown().await.expect("shutdown");
		let mut echoed = Vec::new();
		test_side.read_to_end(&mut echoed).await.expect("read echo");

		serve.await.expect("task").expect("admitted");
		assert_eq!(served.load(Ordering::SeqCst), 1);
		assert_eq!(echoed, b"payload", "the backend must see the stream with the preamble stripped");
	}

	// ---- SharedSecretAuth (Phase 2 — raw-port controls, pre-shared-key preamble). ----

	#[test]
	fn an_empty_secret_is_rejected_offline() {
		// An empty preamble matches unconditionally, so a gate built on it is no gate. Caught
		// at construction, before any Tor launch, rather than silently admitting everyone.
		let err = SharedSecretAuth::new(Vec::new()).err().expect("an empty secret must be rejected");
		assert!(err.to_string().contains("must not be empty"), "unexpected error: {err}");
		let auth = SharedSecretAuth::new(b"s".to_vec()).expect("a one-byte secret is the smallest gate");
		assert_eq!(auth.preamble_len(), 1);
	}

	#[tokio::test]
	async fn the_correct_secret_admits_and_strips_the_preamble() {
		let (backend, served) = backend();
		let secret = b"open-sesame";
		let gate = AuthGate::new(backend, SharedSecretAuth::new(secret.to_vec()).expect("secret"));
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		// The client sends the secret, then its real payload.
		test_side.write_all(secret).await.expect("write secret");
		test_side.write_all(b"GET / HTTP/1.0\r\n\r\n").await.expect("write payload");
		test_side.shutdown().await.expect("shutdown");
		let mut echoed = Vec::new();
		test_side.read_to_end(&mut echoed).await.expect("read echo");

		serve.await.expect("task").expect("the correct secret admits");
		assert_eq!(served.load(Ordering::SeqCst), 1, "the backend must serve an authenticated stream");
		assert_eq!(echoed, b"GET / HTTP/1.0\r\n\r\n", "the backend must see the payload with the secret stripped");
	}

	#[tokio::test]
	async fn a_wrong_secret_is_refused_and_never_reaches_the_backend() {
		let (backend, served) = backend();
		let gate = AuthGate::new(backend, SharedSecretAuth::new(b"open-sesame".to_vec()).expect("secret"));
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		// Same length as the secret so the read completes, but wrong content.
		test_side.write_all(b"open-samsae").await.expect("write wrong secret");
		test_side.write_all(b"payload").await.expect("write payload");
		test_side.shutdown().await.expect("shutdown");

		let err = serve.await.expect("task").expect_err("a wrong secret must be refused");
		assert!(err.to_string().contains("refused"), "unexpected error: {err}");
		assert_eq!(served.load(Ordering::SeqCst), 0, "a wrong secret must never reach the backend");
	}

	#[tokio::test]
	async fn a_truncated_preamble_fails_closed() {
		// The peer connects and sends fewer bytes than the secret, then closes. read_exact
		// cannot complete, so the authorizer errors and AuthGate fails closed.
		let (backend, served) = backend();
		let gate = AuthGate::new(backend, SharedSecretAuth::new(b"open-sesame".to_vec()).expect("secret"));
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		test_side.write_all(b"open").await.expect("write partial secret");
		test_side.shutdown().await.expect("close early");

		let err = serve.await.expect("task").expect_err("a truncated preamble must fail closed");
		assert!(format!("{err:#}").contains("auth preamble"), "the preamble-read cause must be carried: {err:#}");
		assert_eq!(served.load(Ordering::SeqCst), 0, "a truncated preamble must never reach the backend");
	}

	#[tokio::test]
	async fn a_secret_that_is_a_prefix_of_the_sent_bytes_still_admits_exactly_its_length() {
		// Guards the boundary: only `secret.len()` bytes are consumed as the preamble, so a
		// secret that happens to be a prefix of a longer token admits and leaves the rest —
		// including the token's tail — for the backend. (An authorizer that greedily read
		// "as much as looks like the secret" would corrupt the backend stream.)
		let (backend, served) = backend();
		let gate = AuthGate::new(backend, SharedSecretAuth::new(b"key".to_vec()).expect("secret"));
		let (stream, mut test_side) = pipe();

		let serve = tokio::spawn(async move { gate.serve(stream).await });
		test_side.write_all(b"keyboard").await.expect("write");
		test_side.shutdown().await.expect("shutdown");
		let mut echoed = Vec::new();
		test_side.read_to_end(&mut echoed).await.expect("read echo");

		serve.await.expect("task").expect("admitted");
		assert_eq!(served.load(Ordering::SeqCst), 1);
		assert_eq!(echoed, b"board", "only the secret's length is stripped; the rest reaches the backend");
	}

	#[test]
	fn an_auth_gate_reports_authorization_and_merges_the_inner_protection() {
		use crate::ConnectionLimit;

		// A bare AuthGate reports only authorization.
		let gate = AuthGate::new(backend().0, AdmitAll);
		let p = gate.protection();
		assert!(p.authorized, "an AuthGate must report that it authorizes");
		assert_eq!(p.connection_limit, None, "a bare AuthGate adds no connection limit");

		// Nesting composes: AuthGate<ConnectionLimit<_>> reports *both*, so the launch
		// warning names the whole stack in front of the backend.
		let stacked = AuthGate::new(ConnectionLimit::new(backend().0, 4).expect("limit"), AdmitAll);
		let p = stacked.protection();
		assert!(p.authorized, "the outer AuthGate's authorization must be reported");
		assert_eq!(p.connection_limit, Some(4), "the inner ConnectionLimit's cap must be merged in");
		assert_eq!(p.describe().as_deref(), Some("a stream authorizer; a connection limit of 4"));
	}
}
