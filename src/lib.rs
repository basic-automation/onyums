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
//!
//!     serve(app, "my_onion").await.unwrap();
//! }
//! ```

use std::{net::SocketAddr, sync::LazyLock};

use anyhow::{bail, Result};
use arti_client::{TorClient, TorClientConfig};
use axum::{extract::connect_info::Connected as AxumConnected, Router};
use futures::StreamExt;
use hyper::{body::Incoming, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Mutex;
use tor_cell::relaycell::msg::EndReason; // Import EndReason instead of Reason
use tor_cell::relaycell::msg::{Connected, End}; // Import End
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname, StreamRequest};
use tor_proto::stream::{ClientStreamCtrl, IncomingStreamRequest};
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tower_service::Service;
use tracing::{event, span, Level};
extern crate rcgen;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use tokio_rustls::{
	rustls, rustls::pki_types::{pem::PemObject, PrivateKeyDer, PrivatePkcs8KeyDer}, TlsAcceptor
};

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
pub async fn serve(app: Router, nickname: &str) -> Result<()> {
	let serve_trace_span = span!(Level::INFO, "onyums - serve");
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
	let Some(service_name) = service.onion_address() else {
		event!(Level::ERROR, "Failed to get onion service name.");
		bail!("Failed to get onion service name.");
	};
	let service_name = service_name.to_string();
	event!(Level::INFO, "Onion service name: {service_name}");

	ONION_NAME.lock().await.clone_from(&service_name);

	let tls_acceptor = match tls_acceptor() {
		Ok(tls_acceptor) => tls_acceptor,
		Err(e) => {
			event!(Level::ERROR, "Creating TLS acceptor: {:?}", e);
			bail!(format!("Creating TLS acceptor: {:?}", e))
		}
	};

	// create a stream to handle incoming requests
	event!(Level::INFO, "Creating a stream to handle incoming requests...");
	let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
	tokio::pin!(stream_requests);

	event!(Level::INFO, "Waiting for Incoming request...");
	while let Some(stream_request) = stream_requests.next().await {
		let incoming_request_trace_span = span!(Level::INFO, "onyums - incoming_request");
		let _requests_trace_guard = incoming_request_trace_span.enter();
		event!(Level::INFO, "New incoming request found...");
		let app = app.clone();
		let tls_acceptor = tls_acceptor.clone();

		tokio::spawn(async move {
			// handle the incoming request
			let result = handle_stream_request(stream_request, tls_acceptor, app.clone()).await;

			if let Err(err) = result {
				event!(Level::INFO, "Connection closed: Error handling stream request: {err}");
			}
		});
	}

	drop(service);
	event!(Level::INFO, "Onion service exited cleanly.");
	bail!("Onion service exited cleanly");
}

async fn handle_stream_request(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router) -> Result<()> {
	let hadling_request_trace_span = span!(Level::INFO, "onyums - hadling_request");
	let _hadling_request_trace_guard = hadling_request_trace_span.enter();
	match stream_request.request().clone() {
		// Clone request to use `begin` later
		IncomingStreamRequest::Begin(begin) if begin.port() == 443 => {
			// Only handle port 443 for TLS
			// Accept the incoming stream and wrap it in a TLS stream
			event!(Level::INFO, "Accepting the incoming stream and wraping it in a TLS stream...");
			let Ok(onion_service_stream) = stream_request.accept(Connected::new_empty()).await else {
				event!(Level::ERROR, "Failed to accept onion service stream.");
				bail!("failed to accept onion service stream");
			};

			let circuit_id = onion_service_stream.client_stream_ctrl().and_then(|ctrl_stream| ctrl_stream.circuit().map(|circuit| circuit.unique_id().to_string()));
			let connect_info = ConnectionInfo { circuit_id, socket_addr: None };

			// Accept the TLS connection, logging the specific error on failure
			let tls_onion_service_stream = match tls_acceptor.accept(onion_service_stream).await {
				Ok(stream) => stream,
				Err(e) => {
					event!(Level::ERROR, "Failed to accept TLS stream: {:?}", e); // Log the detailed error
					bail!(format!("failed to accept TLS stream: {:?}", e));
				}
			};

			// Wrap the stream in a `tokio_util::compat::Compat` to make it compatible with tokio's `AsyncRead` and `AsyncWrite`.
			event!(Level::INFO, "Wrapping the steam for tokio compatability...");
			let stream = TokioIo::new(tls_onion_service_stream);

			// Hyper also has its own `Service` trait and doesn't use tower. We can use `hyper::service::service_fn` to create a hyper `Service` that calls our app through `tower::Service::call`.
			let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
				// We have to clone `tower_service` because hyper's `Service` uses `&self` whereas tower's `Service` requires `&mut self`.
				// We don't need to call `poll_ready` since `Router` is always ready.
				let connect_info = connect_info.clone();
				let app = app.clone();
				std::thread::spawn(move || {
					event!(Level::INFO, "Creating tokio runtime...");
					let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

					#[allow(clippy::async_yields_async)]
					runtime.block_on(async {
						event!(Level::INFO, "Serving connection...");
						app.clone().into_make_service_with_connect_info::<ConnectionInfo>().call(connect_info.clone()).await.unwrap().call(request)
					})
				})
				.join()
				.unwrap()
			});

			// Serve the connection with hyper's `auto::Builder`.
			event!(Level::INFO, "Serving the connection with hyper...");
			let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(stream, hyper_service).await;

			if let Err(err) = ret {
				event!(Level::ERROR, "Error serving connection: {err}");
			}
		}
		IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
			// Handle Port 80 (Plain HTTP) - Currently rejecting
			event!(Level::INFO, "Rejecting plain HTTP request on port 80.");
			// Construct an End message with a reason using the correct type and constructor
			let end_msg = End::new_with_reason(EndReason::MISC);
			stream_request.reject(end_msg).await?; // Pass the End message
		}
		_ => {
			// Reject the incoming request
			event!(Level::INFO, "Rejecting the incoming request {:?}...", stream_request.request());
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

/* impl AxumConnected<IncomingStream<'_>> for ConnectionInfo {
	fn connect_info(target: IncomingStream<'_>) -> Self {
		Self { circuit_id: None, socket_addr: Some(target.local_addr().unwrap()) }
	}
} */

fn tls_acceptor() -> Result<TlsAcceptor> {
	let onion_name = get_onion_name();
	let subject_alt_names = vec![onion_name];
	let cert = generate_simple_self_signed(subject_alt_names).unwrap();
	let key_der = match PrivatePkcs8KeyDer::from_pem_slice(cert.key_pair.serialize_pem().as_bytes()) {
		Ok(key_der) => PrivateKeyDer::Pkcs8(key_der),
		Err(e) => {
			event!(Level::ERROR, "Error converting key to der: {:?}", e);
			bail!(format!("Error converting key to der: {:?}", e))
		}
	};
	let server_config = match rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key_der) {
		Ok(server_config) => server_config,
		Err(e) => {
			event!(Level::ERROR, "Error creating server config: {:?}", e);
			bail!(format!("Error creating server config: {:?}", e))
		}
	};
	let acceptor = TlsAcceptor::from(Arc::new(server_config));
	Ok(acceptor)
}

#[cfg(test)]
mod tests {
	use axum::{routing::get, Router};

	use super::*;

	#[tokio::test]
	async fn test_serve() {
		let tracing_subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).finish();
		tracing::subscriber::set_global_default(tracing_subscriber).expect("setting default subscriber failed");

		let app = Router::new().route("/", get(|| async { "Hello, World!" }));
		let nickname = "onyums-yum-yum-test2";

		match serve(app, nickname).await {
			Ok(()) => (),
			Err(e) => event!(Level::DEBUG, "Error serving onion service: {e}"),
		}
	}
}
