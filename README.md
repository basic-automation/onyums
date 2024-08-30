# Onyums
Onyums is a simple axum wrapper for serving tor onion services.

## Example
```rust
use axum::{routing::get, Router};
use native_tls::Identity;
use tokio_native_tls::TlsAcceptor;
use onyums::serve;

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));
    let c = include_bytes!("../self_signed_certs/cert.pem");
    let k = include_bytes!("../self_signed_certs/key.pem");
    let identity = Identity::from_pem(c, k).unwrap();
    let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(identity).build().unwrap());

    serve(app, tls_acceptor, "my_onion").await.unwrap();
}
```
