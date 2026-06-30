//! A raw-TCP [`StreamHandler`] — forward an onion stream to a local backend
//! (onyums ROADMAP Phase 3 — arbitrary port → handler mapping).
//!
//! This is the simplest non-HTTP handler and the proof that the [`StreamHandler`]
//! surface tunnels *any* byte protocol over an onion service: a stream that
//! arrives on a registered port is connected to a configured local TCP backend
//! and the two are spliced bidirectionally. The backend protocol (gRPC, SSH, a
//! game server, Lightning) negotiates its own security end-to-end — onyums does
//! not wrap a raw handler in the built-in TLS the HTTP handler uses; the onion
//! circuit already encrypts and authenticates the channel.
//!
//! Unlike most of the live-serve path, this handler is exercised *offline*: its
//! [`serve`](StreamHandler::serve) takes an owned boxed stream, so a test drives
//! it with an in-memory [`tokio::io::duplex`] pair against a loopback echo
//! listener — no live Tor network.

use anyhow::Context;
use tokio::{io::copy_bidirectional, net::TcpStream};

use crate::port_router::{OnionStream, ServeFuture, StreamHandler};

/// Forwards each accepted onion stream to a fixed local TCP backend.
///
/// Register one with [`OnionServiceBuilder::route_port`](crate::OnionServiceBuilder::route_port)
/// to expose a local service over the onion service on a non-HTTP port — e.g.
/// `route_port(9735, RawTcpHandler::new("127.0.0.1:9735"))` to tunnel Lightning.
/// The backend address is resolved fresh per connection, so a backend that is
/// down simply fails that one stream rather than the service.
#[derive(Clone, Debug)]
pub struct RawTcpHandler {
	backend: String,
}

impl RawTcpHandler {
	/// Create a handler that forwards to `backend` (a `host:port` string a
	/// [`TcpStream`] can connect to, typically a loopback address).
	#[must_use]
	pub fn new(backend: impl Into<String>) -> Self {
		Self { backend: backend.into() }
	}

	/// The configured backend address.
	#[must_use]
	pub fn backend(&self) -> &str {
		&self.backend
	}
}

impl StreamHandler for RawTcpHandler {
	fn serve(&self, mut stream: OnionStream) -> ServeFuture {
		// Clone the backend address into the owned future so it does not borrow
		// `self` (which is shared across every circuit behind an `Arc`).
		let backend = self.backend.clone();
		Box::pin(async move {
			let mut upstream = TcpStream::connect(&backend).await.with_context(|| format!("raw-tcp handler: failed to connect to backend {backend}"))?;
			// Splice the onion stream and the backend together until either side
			// closes; `copy_bidirectional` half-closes the peer when one direction
			// hits EOF and drains the other.
			copy_bidirectional(&mut stream, &mut upstream).await.with_context(|| format!("raw-tcp handler: error proxying to backend {backend}"))?;
			Ok(())
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener
	};

	#[test]
	fn new_stores_and_exposes_the_backend() {
		let handler = RawTcpHandler::new("127.0.0.1:9735");
		assert_eq!(handler.backend(), "127.0.0.1:9735");
		// `impl Into<String>` accepts an owned String too.
		let handler = RawTcpHandler::new(String::from("localhost:1234"));
		assert_eq!(handler.backend(), "localhost:1234");
	}

	/// End-to-end proxy test with no live Tor: a loopback echo listener stands in
	/// for the backend, and an in-memory duplex pair stands in for the accepted
	/// onion stream. Bytes written to the client end must round-trip back through
	/// the handler and the echo server.
	#[tokio::test]
	async fn serve_proxies_bytes_to_and_from_the_backend() {
		// A one-shot loopback echo server: accept one connection and copy its
		// input back to it.
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo listener");
		let backend_addr = listener.local_addr().expect("local addr").to_string();
		let echo = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await.expect("accept");
			let (mut r, mut w) = socket.split();
			let _ = tokio::io::copy(&mut r, &mut w).await;
		});

		// The in-memory stand-in for the accepted onion stream.
		let (client, server) = tokio::io::duplex(4096);
		let handler = RawTcpHandler::new(backend_addr);
		let serve = tokio::spawn(async move { handler.serve(Box::pin(server)).await });

		// Drive the client end: send a payload, signal EOF, read the echo back.
		let mut client = client;
		client.write_all(b"ping over an onion service").await.expect("write payload");
		client.shutdown().await.expect("shutdown write half");
		let mut echoed = Vec::new();
		client.read_to_end(&mut echoed).await.expect("read echo");
		assert_eq!(echoed, b"ping over an onion service");

		serve.await.expect("serve task joins").expect("serve succeeds");
		echo.await.expect("echo task joins");
	}

	#[tokio::test]
	async fn serve_errors_when_the_backend_is_unreachable() {
		// Port 1 on loopback has no listener, so the connect fails fast.
		let handler = RawTcpHandler::new("127.0.0.1:1");
		let (_client, server) = tokio::io::duplex(64);
		let err = handler.serve(Box::pin(server)).await.expect_err("unreachable backend must error");
		assert!(err.to_string().contains("failed to connect"), "unexpected error: {err}");
	}
}
