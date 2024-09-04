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

use std::{
	net::SocketAddr, sync::{LazyLock, Mutex}
};

use anyhow::{bail, Result};
use arti_client::{TorClient, TorClientConfig};
use axum::{extract::connect_info::Connected as AxumConnected, serve::IncomingStream, Router};
use futures::StreamExt;
use hyper::{body::Incoming, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio_native_tls::TlsAcceptor;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, HsNickname, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tower_service::Service;

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
	std::env::set_var("RUST_LOG", "hyper,http");

	tracing_subscriber::fmt::init();

	// create a new Tor client
	let config = TorClientConfig::default();
	let Ok(runtime) = TokioNativeTlsRuntime::current() else {
		bail!("failed to get current tokio runtime");
	};
	let client = TorClient::with_runtime(runtime);
	let Ok(client) = client.config(config).create_bootstrapped().await else {
		bail!("failed to create bootstrapped Tor client");
	};

	// launch an onion service
	let Ok(nickname) = nickname.parse::<HsNickname>() else {
		bail!("failed to parse nickname");
	};
	let Ok(svc_cfg) = OnionServiceConfigBuilder::default().nickname(nickname).build() else {
		bail!("failed to build onion service config");
	};
	let Ok((service, request_stream)) = client.launch_onion_service(svc_cfg) else {
		bail!("failed to launch onion service");
	};

	// get the service name
	let Some(service_name) = service.onion_name() else {
		bail!("failed to get onion service name");
	};
	let service_name = service_name.to_string();
	eprintln!("onion service name: {service_name}");

	match ONION_NAME.lock() {
		Ok(mut guard) => {
			(*guard).clone_from(&service_name);
		}
		Err(err) => {
			eprintln!("failed to lock nickname: {err}");
		}
	}

	// create a stream to handle incoming requests
	let stream_requests = tor_hsservice::handle_rend_requests(request_stream);
	tokio::pin!(stream_requests);

	while let Some(stream_request) = stream_requests.next().await {
		let tls_acceptor = tls_acceptor.clone();
		let app = app.clone();

		tokio::spawn(async move {
			// handle the incoming request
			let result = handle_stream_request(stream_request, tls_acceptor.clone(), app.clone()).await;

			if let Err(err) = result {
				eprintln!("error handling stream request: {err}");
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

			//let app = app.clone().into_make_service_with_connect_info::<SocketAddr>().call(socket_addr).await.unwrap();

			// Hyper also has its own `Service` trait and doesn't use tower. We can use `hyper::service::service_fn` to create a hyper `Service` that calls our app through `tower::Service::call`.
			let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
				// We have to clone `tower_service` because hyper's `Service` uses `&self` whereas tower's `Service` requires `&mut self`.
				// We don't need to call `poll_ready` since `Router` is always ready.
				//let _ = request.extensions_mut().insert(connect_info.clone());
				let connect_info = connect_info.clone();

				eprintln!("request: {request:?}");

				let app = app.clone();
				let res = std::thread::spawn(move || {
					let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

					#[allow(clippy::async_yields_async)]
					runtime.block_on(async { app.clone().into_make_service_with_connect_info::<ConnectionInfo>().call(connect_info.clone()).await.unwrap().call(request) })
				})
				.join()
				.unwrap();
				res

				//app.clone().into_make_service_with_connect_info::<SocketAddr>().call(socket_addr).await.unwrap().call(request)
				//app.clone().call(request)
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
		let nickname = "onyums-yum-yum-test";

		serve(app, tls_acceptor, nickname).await.unwrap();
	}
}
