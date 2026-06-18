//! The Tor dimension: per-rendezvous-circuit accounting and policy.
//!
//! A normal axum app cannot express this; onyums calls [`CircuitPolicy`] from its
//! `RendRequest` / `StreamRequest` loop, supplying a host-assigned [`CircuitId`] and
//! the requested [`StreamTarget`]. This generalizes the one-off port-443/80 gate that
//! currently lives in onyums' `handle_stream_request`. See `ROADMAP.md`.

/// What to do with a circuit / stream / request at the Tor layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitAction {
    /// Serve normally.
    Accept,
    /// Force the client through a challenge before serving.
    Challenge,
    /// Refuse this stream/request.
    Reject,
    /// Tear down the whole rendezvous circuit (Arti `shutdown_circuit()`).
    Shutdown,
}

/// Opaque per-rendezvous-circuit identifier assigned by the host (onyums).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CircuitId(pub u64);

/// Where a stream wants to go (the BEGIN-cell target).
#[derive(Clone, Debug)]
pub struct StreamTarget {
    pub port: u16,
    pub host: Option<String>,
}

/// Per-circuit accounting and policy. The host invokes these as circuits, streams,
/// and requests arrive; the returned [`CircuitAction`] drives accept/reject/shutdown.
pub trait CircuitPolicy: Send + Sync {
    /// A new rendezvous circuit was offered.
    fn on_new_circuit(&self, id: &CircuitId) -> CircuitAction;
    /// A new stream opened within an accepted circuit.
    fn on_new_stream(&self, id: &CircuitId, target: &StreamTarget) -> CircuitAction;
    /// A request arrived on an accepted stream (per-circuit rate/quota).
    fn on_request(&self, id: &CircuitId) -> CircuitAction;
}
