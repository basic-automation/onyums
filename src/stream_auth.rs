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
use tracing::{Level, event};

use crate::port_router::{OnionStream, ServeFuture, StreamHandler};

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
}
