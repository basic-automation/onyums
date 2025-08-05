![logo](./assets/onyums-logo.svg)
<br><br>
![docs.rs](https://img.shields.io/docsrs/onyums?style=for-the-badge) ![Crates.io Total Downloads](https://img.shields.io/crates/d/onyums?style=for-the-badge) ![Crates.io License](https://img.shields.io/crates/l/onyums?style=for-the-badge)
<br><br>

Onyums is a simple axum wrapper for serving tor onion services. It provides the `ConnectionInfo` extractor to differentiate connections made over tor since the concept of `SocketAddrs` does not exist on private connections.

*******************
####  **NEW! - Onyums now supports websockets over Tor!**
####  **NEW! - Onyums now generates self-signed certs automatically on the fly!**
#### **NEW! - Onyums now automatically upgrades http urls to https with no extra work on your end.**
*******************


## Hello world example
```rust
use onyums::{serve, routing::get, Router};

#[tokio::main]
async fn main() {
	// spawn an onyums server on a new thread and return the onion address
	tokio::spawn(async {
		let app = Router::new().route("/", axum_get(|| async { "Hello, World!" }));
		serve(app, "my_onion").await.unwrap();
	});

        // wait until `get_onion_name()` returns a non-empty String
        // then the server is ready
        let mut onion_name = String::new();
        while onion_name.is_empty() {
		onion_name = get_onion_name();

                // wait for 200 milliseconds before checking again
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
	}
	println!("Onion Address: {onion_name}");
}
```
****

## Websocket example
```rust
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use axum_extra::TypedHeader;

use std::borrow::Cow;
use std::ops::ControlFlow;
use onyums::{serve, ConnectionInfo};

#[tokio::main]
async fn main() {
        // build our application with some routes
        let app = Router::new().route("/ws", get(ws_handler));

        // start the serve
        // pass in the router and the server nickname (used to generate an onion address).
        serve(app, "my_onion").await.unwrap();
}

/// The handler for the HTTP request (this gets called when the HTTP GET lands at the start
/// of websocket negotiation). After this completes, the actual switching from HTTP to
/// websocket protocol will occur.
/// This is the last point where we can extract TCP/IP metadata such as IP address of the client
/// as well as things from HTTP headers such as user-agent of the browser etc.
async fn ws_handler(ws: WebSocketUpgrade, user_agent: Option<TypedHeader<headers::UserAgent>>, ConnectInfo(connection_info): ConnectInfo<ConnectionInfo>) -> impl IntoResponse {
        let default_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
	let parsed_addr = connection_info.socket_addr.unwrap_or(default_addr).to_string();
	let circuit_id = connection_info.circuit_id.unwrap_or_default();

	let addr = if parsed_addr == default_addr.to_string() { circuit_id } else { parsed_addr };

        let user_agent = if let Some(TypedHeader(user_agent)) = user_agent { user_agent.to_string() } else { String::from("Unknown browser") };
        println!("`{user_agent}` at {addr} connected.");
        // finalize the upgrade process by returning upgrade callback.
        // we can customize the callback by sending additional info such as address.
        ws.on_upgrade(move |socket| handle_socket(socket, addr))
}

/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: WebSocket, who: String) {
        // send a ping (unsupported by some browsers) just to kick things off and get a response
        if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
                println!("Pinged {who}...");
        } else {
                println!("Could not send ping {who}!");
                // no Error here since the only thing we can do is to close the connection.
                // If we can not send messages, there is no way to salvage the statemachine anyway.
                return;
        }

        // receive single message from a client (we can either receive or send with socket).
        // this will likely be the Pong for our Ping or a hello message from client.
        // waiting for message from a client will block this task, but will not block other client's
        // connections.
        if let Some(msg) = socket.recv().await {
                if let Ok(msg) = msg {
                        if process_message(msg, who).is_break() {
                                return;
                        }
                } else {
                        println!("client {who} abruptly disconnected");
                        return;
                }
        }

        // Since each client gets individual statemachine, we can pause handling
        // when necessary to wait for some external event (in this case illustrated by sleeping).
        // Waiting for this client to finish getting its greetings does not prevent other clients from
        // connecting to server and receiving their greetings.
        for i in 1..5 {
                if socket.send(Message::Text(format!("Hi {i} times!"))).await.is_err() {
                        println!("client {who} abruptly disconnected");
                        return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // By splitting socket we can send and receive at the same time. In this example we will send
        // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
        let (mut sender, mut receiver) = socket.split();

        // Spawn a task that will push several messages to the client (does not matter what client does)
        let mut send_task = tokio::spawn(async move {
                let n_msg = 20;
                for i in 0..n_msg {
                        // In case of any websocket error, we exit.
                        if sender.send(Message::Text(format!("Server message {i} ..."))).await.is_err() {
                                return i;
                        }

                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }

                println!("Sending close to {who}...");
                if let Err(e) = sender.send(Message::Close(Some(CloseFrame {code: axum::extract::ws::close_code::NORMAL, reason: Cow::from("Goodbye"),}))).await {
                        println!("Could not send Close due to {e}, probably it is ok?");
                }
                n_msg
        });

        // This second task will receive messages from client and print them on server console
        let mut recv_task = tokio::spawn(async move {
                let mut cnt = 0;
                while let Some(Ok(msg)) = receiver.next().await {
                        cnt += 1;
                        // print message and break if instructed to do so
                        if process_message(msg, who).is_break() {
                                break;
                        }
                }
                cnt
        });

        // If any one of the tasks exit, abort the other.
        tokio::select! {
                rv_a = (&mut send_task) => {
                        match rv_a {
                                Ok(a) => println!("{a} messages sent to {who}"),
                                Err(a) => println!("Error sending messages {a:?}")
                        }
                        recv_task.abort();
                },
                rv_b = (&mut recv_task) => {
                        match rv_b {
                                Ok(b) => println!("Received {b} messages"),
                                Err(b) => println!("Error receiving messages {b:?}")
                        }
                        send_task.abort();
                }
        }

        // returning from the handler closes the websocket connection
        println!("Websocket context {who} destroyed");
}

/// helper to print contents of messages to stdout. Has special treatment for Close.
fn process_message(msg: Message, who: String) -> ControlFlow<(), ()> {
        match msg {
                Message::Text(t) => {
                        println!(">>> {who} sent str: {t:?}");
                }
                Message::Binary(d) => {
                        println!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
                }
                Message::Close(c) => {
                        if let Some(cf) = c {
                                println!(">>> {} sent close with code {} and reason `{}`", who, cf.code, cf.reason);
                        } else {
                                println!(">>> {who} somehow sent close message without CloseFrame");
                        }
                        return ControlFlow::Break(());
                }
                Message::Pong(v) => {
                        println!(">>> {who} sent pong with {v:?}");
                }

                // You should never need to manually handle Message::Ping, as axum's websocket library
                // will do so for you automagically by replying with Pong and copying the v according to
                // spec. But if you need the contents of the pings you can see them here.
                Message::Ping(v) => {
                        println!(">>> {who} sent ping with {v:?}");
                }
        }
        ControlFlow::Continue(())
}
```