#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]
#![feature(addr_parse_ascii)]

//! # Onyums
//! Onyums is a simple axum wrapper for serving tor onion services.
//!
//! # Example
//! ```rust
//! use axum::{routing::get, Router};
//! use native_tls::Identity;
//! use tokio_native_tls::TlsAcceptor;
//! use onyums::serve;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, World!" }));
//!     let c = include_bytes!("../self_signed_certs/cert.pem");
//!     let k = include_bytes!("../self_signed_certs/key.pem");
//!     let identity = Identity::from_pem(c, k).unwrap();
//!     let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(identity).build().unwrap());
//!
//!     serve(app, tls_acceptor, "my_onion").await.unwrap();
//! }
//! ```

use std::{net::SocketAddr, sync::LazyLock};

use anyhow::{bail, Result};
use arti_client::{TorClient, TorClientConfig};
use axum::{extract::connect_info::Connected as AxumConnected, serve::IncomingStream, Router};
use futures::StreamExt;
use hyper::{body::Incoming, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Mutex;
use tokio_native_tls::TlsAcceptor;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tower_service::Service;
use tracing::{event, span, Level};

static ONION_NAME: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));

pub fn get_onion_name() -> String {
	ONION_NAME.try_lock().map_or_else(|_| String::new(), |guard| (*guard.clone()).to_string())
}

/// Serve a web application over an onion service.
///
/// This function creates a new Tor client, launches an onion service, and serves a web application.
///
/// # Arguments
/// `app` - The axum `Router` to serve.
/// `tls_acceptor` - The `TlsAcceptor` to use for the web server.
/// `nickname` - The nickname of the onion service.
///
/// # Returns
/// An `anyhow::Result` indicating success or failure.
///
/// # Errors
/// This function returns an error if any of the following occur:
/// - The nickname fails to parse.
/// - The onion service fails to launch.
/// - The TLS acceptor fails to create.
/// - The web server fails to start.
/// - The Tor client fails to create.
/// - The Tor client fails to bootstrap.
/// - The Tor client fails to create a stream.
/// - The Tor client fails to connect to the onion service.
pub async fn serve(app: Router, tls_acceptor: TlsAcceptor, nickname: &str) -> Result<()> {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_max_level(Level::INFO).finish();
        tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

        let serve_trace_span = span!(Level::INFO, "serve");
        let _info_trace_guard = serve_trace_span.enter();
        event!(Level::INFO, "Setting up onion service...");

	// create a new Tor client
        event!(Level::INFO, "Creating Tor client...");
	let config = TorClientConfig::default();
	let Ok(runtime) = TokioNativeTlsRuntime::current() else {
                event!(Level::ERROR, "Failed to get current tokio runtime.");
		bail!("Failed to get current tokio runtime.");
	};
	let client = TorClient::with_runtime(runtime);
	let Ok(client) = client.config(config).create_bootstrapped().await else {
                event!(Level::ERROR, "Failed to create bootstrapped Tor client.");
		bail!("Failed to create bootstrapped Tor client.");
	};

	// launch an onion service
        event!(Level::INFO, "Launching onion service...");
	let Ok(nickname) = nickname.parse::<HsNickname>() else {
                event!(Level::ERROR, "Failed to parse nickname.");
		bail!("Failed to parse nickname.");
	};
	let Ok(svc_cfg) = OnionServiceConfigBuilder::default().nickname(nickname).build() else {
                event!(Level::ERROR, "Failed to build onion service config.");
		bail!("Failed to build onion service config.");
	};
	let Ok((service, request_stream)) = client.launch_onion_service(svc_cfg) else {
                event!(Level::ERROR, "Failed to launch onion service.");
                bail!("Failed to launch onion service.");
	};

	// get the service name
        event!(Level::INFO, "Getting the onion service name...");
	let Some(service_name) = service.onion_name() else {
                event!(Level::ERROR, "Failed to get onion service name.");
		bail!("Failed to get onion service name.");
	};
	let service_name = service_name.to_string();
        event!(Level::INFO, "Onion service name: {service_name}");

	ONION_NAME.lock().await.clone_from(&service_name);

	// create a stream to handle incoming requests
        event!(Level::INFO, "Creating a stream to handle incoming requests...");
	let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
	tokio::pin!(stream_requests);

        event!(Level::INFO, "Handling incoming request...");
	while let Some(stream_request) = stream_requests.next().await {
                let serve_trace_span = span!(Level::INFO, "handle_incoming_request");
                let _requests_trace_guard = serve_trace_span.enter();
                event!(Level::INFO, "New incoming request found...");
		let tls_acceptor = tls_acceptor.clone();
		let app = app.clone();

		tokio::spawn(async move {
			// handle the incoming request
			let result = handle_stream_request(stream_request, tls_acceptor.clone(), app.clone()).await;

			if let Err(err) = result {
                                event!(Level::ERROR, "Error handling stream request: {err}");
			}
		});
	}

	drop(service);
	bail!("onion service exited cleanly");
}

async fn handle_stream_request(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router) -> Result<()> {
	match stream_request.request() {
		IncomingStreamRequest::Begin(begin) if begin.port() == 80 || begin.port() == 443 => {
			// Accept the incoming stream and wrap it in a TLS stream
			let Ok(onion_service_stream) = stream_request.accept(Connected::new_empty()).await else {
				bail!("failed to accept onion service stream");
			};

			let connect_info = ConnectionInfo { circuit_id: Some(onion_service_stream.circuit().unique_id().to_string()), socket_addr: None };

			let Ok(tls_onion_service_stream) = tls_acceptor.accept(onion_service_stream).await else {
				bail!("failed to accept TLS stream");
			};

			// Wrap the stream in a `tokio_util::compat::Compat` to make it compatible with tokio's `AsyncRead` and `AsyncWrite`.
			let stream = TokioIo::new(tls_onion_service_stream);

			// Hyper also has its own `Service` trait and doesn't use tower. We can use `hyper::service::service_fn` to create a hyper `Service` that calls our app through `tower::Service::call`.
			let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
				// We have to clone `tower_service` because hyper's `Service` uses `&self` whereas tower's `Service` requires `&mut self`.
				// We don't need to call `poll_ready` since `Router` is always ready.
				let connect_info = connect_info.clone();
				let app = app.clone();
				let res = std::thread::spawn(move || {
					println!("create tokio runtime.");
					let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

					#[allow(clippy::async_yields_async)]
					runtime.block_on(async {
						println!("serving connection.");
						app.clone().into_make_service_with_connect_info::<ConnectionInfo>().call(connect_info.clone()).await.unwrap().call(request)
					})
				})
				.join()
				.unwrap();
				res
			});

			let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(stream, hyper_service).await;

			if let Err(err) = ret {
				eprintln!("error serving connection: {err}");
			}
		}
		_ => {
			eprintln!("rejecting request: {:?}", stream_request.request());
			stream_request.shutdown_circuit()?;
		}
	}

	Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
	pub circuit_id: Option<String>,
	pub socket_addr: Option<SocketAddr>,
}

impl AxumConnected<Request<Incoming>> for ConnectionInfo {
	fn connect_info(target: Request<Incoming>) -> Self {
		Self { circuit_id: target.extensions().get::<Self>().unwrap().circuit_id.clone(), socket_addr: None }
	}
}

impl AxumConnected<Self> for ConnectionInfo {
	fn connect_info(target: Self) -> Self {
		target
	}
}

impl AxumConnected<IncomingStream<'_>> for ConnectionInfo {
	fn connect_info(target: IncomingStream<'_>) -> Self {
		Self { circuit_id: None, socket_addr: Some(target.local_addr().unwrap()) }
	}
}

#[cfg(test)]
mod tests {
	use axum::{routing::get, Router};
	use native_tls::Identity;
	use tokio_native_tls::TlsAcceptor;

	use super::*;

	#[tokio::test]
	async fn test_serve() {
		let app = Router::new().route("/", get(|| async { "Hello, World!" }));

		let c = include_bytes!("../self_signed_certs/cert.pem");
		let k = include_bytes!("../self_signed_certs/key.pem");
		let cert = Identity::from_pkcs8(c, k).unwrap();
		let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());
		let nickname = "onyums-yum-yum-test2";

		match serve(app, tls_acceptor, nickname).await {
			Ok(()) => (),
			Err(e) => event!(Level::DEBUG, "Error serving onion service: {e}"),
		}
	}
}
