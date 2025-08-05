#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]
#![feature(addr_parse_ascii)]

//! # Onyums
//! Onyums is a simple axum wrapper for serving tor onion services.
//!
//! # Example
//! ```rust
//! use onyums::{serve, routing::get, Router};
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
use axum::extract::connect_info::Connected as AxumConnected;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use http_body_util::Empty;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::Mutex;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname, RendRequest, RunningOnionService, StreamRequest};
use tor_proto::stream::{ClientStreamCtrl, IncomingStreamRequest};
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tower_service::Service;
use tracing::{event, span, Level};
extern crate rcgen;
use std::sync::Arc;

pub use axum::*;
use rcgen::generate_simple_self_signed;
use tokio_rustls::{
	rustls, rustls::pki_types::{pem::PemObject, PrivateKeyDer, PrivatePkcs8KeyDer}, TlsAcceptor
};

static ONION_NAME: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(String::new()));

pub fn get_onion_name() -> String {
	ONION_NAME.try_lock().map_or_else(|_| String::new(), |guard| (*guard.clone()).to_string())
}

/// Sets up and bootstraps a Tor client.
async fn setup_tor_client() -> Result<TorClient<TokioNativeTlsRuntime>> {
	event!(Level::INFO, "Creating Tor client...");
	let config = TorClientConfig::default();
	let runtime = TokioNativeTlsRuntime::current().map_err(|_| anyhow::anyhow!("Failed to get current tokio runtime."))?;
	let client = TorClient::with_runtime(runtime);
	client.config(config).create_bootstrapped().await.map_err(|_| anyhow::anyhow!("Failed to create bootstrapped Tor client."))
}

/// Launches an onion service with the given nickname.
fn launch_onion_service(client: &TorClient<TokioNativeTlsRuntime>, nickname: &str) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)> {
	event!(Level::INFO, "Launching onion service...");
	let nickname = nickname.parse::<HsNickname>().map_err(|_| anyhow::anyhow!("Failed to parse nickname."))?;
	let svc_cfg = OnionServiceConfigBuilder::default().nickname(nickname).build().map_err(|_| anyhow::anyhow!("Failed to build onion service config."))?;
	client.launch_onion_service(svc_cfg).map_err(|_| anyhow::anyhow!("Failed to launch onion service."))
}

/// Retrieves and stores the onion service name.
async fn get_and_store_onion_name(service: &Arc<RunningOnionService>) -> Result<String> {
	event!(Level::INFO, "Getting the onion service name...");
	let service_name = service.onion_address().ok_or_else(|| anyhow::anyhow!("Failed to get onion service name."))?.to_string();
	event!(Level::INFO, "Onion service name: {service_name}");

	// Ensure we store the name with .onion suffix, but not double .onion
	let clean_name = if service_name.ends_with(".onion.onion") {
		service_name.strip_suffix(".onion").unwrap_or(&service_name).to_string()
	} else if !service_name.ends_with(".onion") {
		format!("{service_name}.onion")
	} else {
		service_name
	};

	event!(Level::INFO, "Cleaned onion service name: {clean_name}");
	ONION_NAME.lock().await.clone_from(&clean_name);
	Ok(clean_name)
}

/// Handles incoming stream requests by spawning tasks to process them.
async fn handle_incoming_requests(mut stream_requests: impl Stream<Item = StreamRequest> + Send + Unpin, app: Router, tls_acceptor: TlsAcceptor) -> Result<()> {
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
	Ok(())
}

/// Initializes the onion service and returns the service and request stream.
async fn initialize_onion_service(client: &TorClient<TokioNativeTlsRuntime>, nickname: &str) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)> {
	let (service, request_stream) = launch_onion_service(client, nickname)?;
	let _service_name = get_and_store_onion_name(&service).await?;
	Ok((service, request_stream))
}

/// Prepares the request handling stream.
fn prepare_request_stream(request_stream: impl Stream<Item = RendRequest>) -> impl Stream<Item = StreamRequest> {
	event!(Level::INFO, "Creating a stream to handle incoming requests...");
	tor_hsservice::handle_rend_requests(request_stream)
}

/// Serve a web application over an onion service.
///
/// This function creates a new Tor client, launches an onion service, and serves a web application.
///
/// # Arguments
/// `app` - The axum `Router` to serve.
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

	let client = setup_tor_client().await?;

	let (service, request_stream) = initialize_onion_service(&client, nickname).await?;

	let tls_acceptor = tls_acceptor()?;

	let stream_requests = prepare_request_stream(request_stream);
	tokio::pin!(stream_requests);

	handle_incoming_requests(stream_requests, app, tls_acceptor).await?;

	drop(service);
	event!(Level::INFO, "Onion service exited cleanly.");
	bail!("Onion service exited cleanly");
}

/// Handles a TLS connection on port 443.
async fn handle_tls_connection(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router) -> Result<()> {
	event!(Level::INFO, "Accepting the incoming stream and wrapping it in a TLS stream...");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|_| anyhow::anyhow!("failed to accept onion service stream"))?;

	let circuit_id = onion_service_stream.client_stream_ctrl().and_then(|ctrl_stream| ctrl_stream.circuit().map(|circuit| circuit.unique_id().to_string()));
	let connect_info = ConnectionInfo { circuit_id, socket_addr: None };

	// Accept the TLS connection, logging the specific error on failure
	let tls_onion_service_stream = tls_acceptor.accept(onion_service_stream).await.map_err(|e| anyhow::anyhow!("failed to accept TLS stream: {:?}", e))?;

	// Wrap the stream in a `TokioIo` to make it compatible with tokio's `AsyncRead` and `AsyncWrite`.
	event!(Level::INFO, "Wrapping the stream for tokio compatibility...");
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
	hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(stream, hyper_service).await.map_err(|err| anyhow::anyhow!("Error serving connection: {err}"))
}

/// Handles a plain HTTP request on port 80 by redirecting to HTTPS.
async fn handle_http_redirect(stream_request: StreamRequest, requested_host: String) -> Result<()> {
	event!(Level::INFO, "Accepting plain HTTP request on port 80 and redirecting to HTTPS.");
	let onion_service_stream = stream_request.accept(Connected::new_empty()).await.map_err(|_| anyhow::anyhow!("failed to accept onion service stream"))?;

	let stream = TokioIo::new(onion_service_stream);

	let hyper_service = hyper::service::service_fn(move |req: Request<Incoming>| {
		let host = requested_host.clone();
		let path = req.uri().path_and_query().map_or("", |p| p.as_str());
		let redirect_uri = format!("https://{host}{path}");
		async move { Ok::<_, std::convert::Infallible>(Response::builder().status(StatusCode::MOVED_PERMANENTLY).header("Location", redirect_uri).body(Empty::<Bytes>::new()).unwrap()) }
	});

	hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).http1_only().serve_connection(stream, hyper_service).await.map_err(|err| anyhow::anyhow!("Error serving HTTP redirect: {err}"))
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

// Move tls_acceptor function up, before serve
fn tls_acceptor() -> Result<TlsAcceptor> {
	let onion_name = get_onion_name();
	let subject_alt_names = vec![onion_name];
	let cert = generate_simple_self_signed(subject_alt_names).unwrap();

	let key_der = match PrivatePkcs8KeyDer::from_pem_slice(cert.signing_key.serialize_pem().as_bytes()) {
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

// Then handle_stream_request
async fn handle_stream_request(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router) -> Result<()> {
	let handling_request_trace_span = span!(Level::INFO, "onyums - handling_request");
	let _handling_request_trace_guard = handling_request_trace_span.enter();
	match stream_request.request().clone() {
		// Clone request to use `begin` later
		IncomingStreamRequest::Begin(begin) if begin.port() == 443 => {
			// Only handle port 443 for TLS
			handle_tls_connection(stream_request, tls_acceptor, app).await
		}
		IncomingStreamRequest::Begin(_begin) if _begin.port() == 80 => {
			// Handle Port 80 (Plain HTTP) - Redirect to HTTPS
			let onion_name = get_onion_name();
			handle_http_redirect(stream_request, onion_name).await
		}
		_ => {
			// Reject the incoming request
			event!(Level::INFO, "Rejecting the incoming request {:?}...", stream_request.request());
			stream_request.shutdown_circuit().map_err(|e| anyhow::anyhow!("Failed to shutdown circuit: {e}"))
		}
	}
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
