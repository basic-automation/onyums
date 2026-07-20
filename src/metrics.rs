//! Per-service circuit/stream metrics and the Prometheus text-format exporter
//! (onyums ROADMAP Phase 4 — observability).
//!
//! [`ServiceMetrics`] is the public, immutable snapshot; [`CircuitMetrics`] is the
//! shared atomic backing the accept loop increments. [`fleet_prometheus`] and
//! `ServiceMetrics::to_prometheus*` render the exposition. Extracted from `lib.rs`
//! as the first slice of the Phase 0 module split.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{OnionAddress, circuit_gate};

/// A point-in-time snapshot of a service's cumulative circuit/stream counters.
///
/// Returned by [`OnionServiceHandle::metrics`](crate::OnionServiceHandle::metrics) (onyums ROADMAP Phase 4 — per-service
/// metrics). Every field is a monotonic total since the service launched (a counter, not
/// a gauge), so two snapshots subtract to a rate or a delta — feed them to a
/// Prometheus/OpenTelemetry exporter, or print a health line. `circuits_offered` counts
/// every offer; `circuits_accepted + circuits_rejected` can be slightly less, the
/// difference being circuits arti failed to accept for transport reasons (neither a
/// policy decision nor served).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceMetrics {
	/// Rendezvous circuits offered to the service — one per arti `RendRequest`.
	pub circuits_offered: u64,
	/// Circuits accepted into service after the circuit-level policy gate.
	pub circuits_accepted: u64,
	/// Circuits the circuit-level policy rejected (or tore down) at the offer.
	pub circuits_rejected: u64,
	/// Circuits refused because the host-global concurrency limit was already full.
	///
	/// Deliberately its own counter rather than folded into
	/// [`circuits_rejected`](Self::circuits_rejected): a policy rejection is a verdict
	/// about *that* circuit, while this one says nothing about the circuit and
	/// everything about the service being at capacity. Conflating them would make a
	/// service that is simply too small look like it is under attack, and vice versa —
	/// which is exactly backwards for the operator deciding whether to raise the limit
	/// or to start refusing traffic upstream.
	pub circuits_refused_at_capacity: u64,
	/// Streams handed to a handler after passing the per-stream policy gate.
	pub streams_served: u64,
	/// Streams the per-stream policy rejected while leaving the circuit alive.
	pub streams_rejected: u64,
	/// Streams whose policy action tore down the whole circuit.
	pub streams_shutdown: u64,
	/// Streams refused because the host-global concurrent-stream limit was already full.
	///
	/// The per-stream counterpart to
	/// [`circuits_refused_at_capacity`](Self::circuits_refused_at_capacity), and separate
	/// from [`streams_rejected`](Self::streams_rejected) for the same reason: a policy
	/// rejection is a verdict about that stream, this one means the service is full.
	pub streams_refused_at_capacity: u64,
}

/// One service's eight counter samples as `(prometheus_metric_name, HELP_text, value)`
/// triples in the shared family order — the return of
/// `prometheus_series`, named so the per-service and fleet exporters
/// share one type.
type PrometheusSeries = [(&'static str, &'static str, u64); 8];

impl ServiceMetrics {
	/// The per-counter activity between an `earlier` snapshot and this one: `self`
	/// minus `earlier`, field by field, saturating at `0`.
	///
	/// The counters are monotonic, so over a real interval `self >= earlier` and the
	/// result is the number of circuits/streams in each category during it — divide by
	/// the elapsed time for a rate. Saturating (rather than panicking on underflow) means
	/// accidentally swapping the operands yields zeros, not a crash.
	#[must_use]
	pub const fn since(&self, earlier: Self) -> Self {
		Self {
			circuits_offered: self.circuits_offered.saturating_sub(earlier.circuits_offered),
			circuits_accepted: self.circuits_accepted.saturating_sub(earlier.circuits_accepted),
			circuits_rejected: self.circuits_rejected.saturating_sub(earlier.circuits_rejected),
			circuits_refused_at_capacity: self.circuits_refused_at_capacity.saturating_sub(earlier.circuits_refused_at_capacity),
			streams_served: self.streams_served.saturating_sub(earlier.streams_served),
			streams_rejected: self.streams_rejected.saturating_sub(earlier.streams_rejected),
			streams_shutdown: self.streams_shutdown.saturating_sub(earlier.streams_shutdown),
			streams_refused_at_capacity: self.streams_refused_at_capacity.saturating_sub(earlier.streams_refused_at_capacity),
		}
	}

	/// Circuits that were offered but neither accepted nor rejected by the policy gate —
	/// `circuits_offered − (circuits_accepted + circuits_rejected)`, saturating at `0`.
	///
	/// These are the circuits arti failed to accept for transport reasons (the offer
	/// arrived but `RendRequest::accept` errored) rather than any policy decision — a
	/// distinct health signal from a policy rejection. Saturating so a torn read across
	/// the independent `Relaxed` counter loads can never underflow-panic; over a settled
	/// snapshot the identity holds exactly.
	#[must_use]
	pub const fn circuits_failed_transport(&self) -> u64 {
		self.circuits_offered.saturating_sub(self.circuits_accepted.saturating_add(self.circuits_rejected))
	}

	/// All streams the per-stream gate saw, whatever the disposition —
	/// `streams_served + streams_rejected + streams_shutdown`, saturating at `u64::MAX`.
	///
	/// The denominator for a served-fraction or reject-rate over the stream gate.
	#[must_use]
	pub const fn total_streams(&self) -> u64 {
		self.streams_served.saturating_add(self.streams_rejected).saturating_add(self.streams_shutdown)
	}

	/// The six counters as `(prometheus_metric_name, HELP_text, value)` triples, in a
	/// stable order. The single source of truth both [`to_prometheus`](Self::to_prometheus)
	/// and [`to_prometheus_labeled`](Self::to_prometheus_labeled) render from, so the two
	/// exports can never drift in name, help, or ordering.
	const fn prometheus_series(&self) -> PrometheusSeries {
		[
			("onyums_circuits_offered_total", "Rendezvous circuits offered to the service (one per arti RendRequest).", self.circuits_offered),
			("onyums_circuits_accepted_total", "Circuits accepted after the circuit-level policy gate.", self.circuits_accepted),
			("onyums_circuits_rejected_total", "Circuits the circuit-level policy rejected or tore down at the offer.", self.circuits_rejected),
			("onyums_circuits_refused_at_capacity_total", "Circuits refused because the host-global concurrency limit was full.", self.circuits_refused_at_capacity),
			("onyums_streams_served_total", "Streams handed to a handler after passing the per-stream policy gate.", self.streams_served),
			("onyums_streams_rejected_total", "Streams the per-stream policy rejected while leaving the circuit alive.", self.streams_rejected),
			("onyums_streams_shutdown_total", "Streams whose policy action tore down the whole circuit.", self.streams_shutdown),
			("onyums_streams_refused_at_capacity_total", "Streams refused because the host-global concurrent-stream limit was full.", self.streams_refused_at_capacity),
		]
	}

	/// Render these counters in the Prometheus text exposition format (version 0.0.4) —
	/// each counter as a `# HELP` / `# TYPE … counter` pair followed by its value, ready
	/// to serve at a `/metrics` endpoint or hand to an OpenTelemetry scraper.
	///
	/// Metric names carry the conventional `_total` suffix for a monotonic counter. The
	/// output ends with a trailing newline, per the format. Use
	/// [`to_prometheus_labeled`](Self::to_prometheus_labeled) to attach a `service=…`
	/// label when several onion services scrape into one exposition.
	#[must_use]
	pub fn to_prometheus(&self) -> String {
		self.to_prometheus_labeled(&[])
	}

	/// Like [`to_prometheus`](Self::to_prometheus), but attaches `labels` (e.g.
	/// `&[("service", "abcd….onion")]`) to every series so multiple services can be
	/// distinguished in one scrape.
	///
	/// Label values are escaped per the exposition format (`\\`, `\"`, `\n`). An empty
	/// `labels` slice produces bare metric lines identical to [`to_prometheus`](Self::to_prometheus).
	#[must_use]
	pub fn to_prometheus_labeled(&self, labels: &[(&str, &str)]) -> String {
		let label_block = format_prometheus_labels(labels);
		let mut out = String::new();
		for (name, help, value) in self.prometheus_series() {
			out.push_str("# HELP ");
			out.push_str(name);
			out.push(' ');
			out.push_str(help);
			out.push('\n');
			out.push_str("# TYPE ");
			out.push_str(name);
			out.push_str(" counter\n");
			out.push_str(name);
			out.push_str(&label_block);
			out.push(' ');
			out.push_str(&value.to_string());
			out.push('\n');
		}
		out
	}
}

/// Render `metrics` as a Prometheus exposition labeled with the service's `.onion`
/// address under the conventional `service` label key — the body of
/// [`OnionServiceHandle::metrics_prometheus`](crate::OnionServiceHandle::metrics_prometheus), factored out so the labeling choice
/// (which key, which value) is offline-testable without a running service.
pub fn service_metrics_prometheus(metrics: ServiceMetrics, address: &OnionAddress) -> String {
	metrics.to_prometheus_labeled(&[("service", address.as_str())])
}

/// Render several services' metrics into **one valid** Prometheus exposition.
///
/// Each metric's `# HELP` / `# TYPE` header is emitted exactly once, followed by every
/// service's sample under its own `service="<label>"` label. This is the correct way to
/// scrape a fleet at a single `/metrics` endpoint.
/// Concatenating per-service [`ServiceMetrics::to_prometheus`] /
/// [`OnionServiceHandle::metrics_prometheus`](crate::OnionServiceHandle::metrics_prometheus) outputs instead repeats the HELP/TYPE
/// headers for every service, which the Prometheus/OpenMetrics text format forbids
/// (metadata must appear at most once per metric family) and strict parsers reject.
///
/// Each item is `(service_label, metrics)`; the label is escaped and rides as
/// `service="…"`. Feed it from a set of handles with
/// `fleet_prometheus(handles.iter().map(|h| (h.onion_address().as_str(), h.metrics())))`.
/// An empty iterator yields the empty string. The family metadata (names, help, order)
/// comes from the same `prometheus_series` the per-service exporter
/// uses, so the two exports can never disagree.
#[must_use]
pub fn fleet_prometheus<'a>(services: impl IntoIterator<Item = (&'a str, ServiceMetrics)>) -> String {
	// Snapshot each service's series once (name/help/value in the shared order), paired
	// with its rendered `service="…"` label block — we then walk metric-family-outer,
	// service-inner so each header prints once.
	let rows: Vec<(String, PrometheusSeries)> = services.into_iter().map(|(label, metrics)| (format_prometheus_labels(&[("service", label)]), metrics.prometheus_series())).collect();

	let Some((_, first_series)) = rows.first() else {
		return String::new();
	};

	let mut out = String::new();
	for family in 0..first_series.len() {
		let (name, help, _) = first_series[family];
		out.push_str("# HELP ");
		out.push_str(name);
		out.push(' ');
		out.push_str(help);
		out.push('\n');
		out.push_str("# TYPE ");
		out.push_str(name);
		out.push_str(" counter\n");
		for (label_block, series) in &rows {
			let (_, _, value) = series[family];
			out.push_str(name);
			out.push_str(label_block);
			out.push(' ');
			out.push_str(&value.to_string());
			out.push('\n');
		}
	}
	out
}

/// Render a `{k="v",…}` Prometheus label block, escaping each value; the empty slice
/// yields the empty string (no braces), so an unlabeled series stays bare.
fn format_prometheus_labels(labels: &[(&str, &str)]) -> String {
	if labels.is_empty() {
		return String::new();
	}
	let mut out = String::from("{");
	for (i, (key, value)) in labels.iter().enumerate() {
		if i > 0 {
			out.push(',');
		}
		out.push_str(key);
		out.push_str("=\"");
		out.push_str(&escape_prometheus_label_value(value));
		out.push('"');
	}
	out.push('}');
	out
}

/// Escape a Prometheus label value: backslash, double-quote, and newline, per the text
/// exposition format. Other bytes pass through unchanged.
fn escape_prometheus_label_value(value: &str) -> String {
	let mut out = String::with_capacity(value.len());
	for ch in value.chars() {
		match ch {
			'\\' => out.push_str("\\\\"),
			'"' => out.push_str("\\\""),
			'\n' => out.push_str("\\n"),
			_ => out.push(ch),
		}
	}
	out
}

/// Shared atomic counters backing [`ServiceMetrics`]: incremented from the rendezvous
/// loop and snapshotted by [`OnionServiceHandle::metrics`](crate::OnionServiceHandle::metrics).
///
/// `Relaxed` ordering throughout — each counter is an independent monotonic total, not a
/// lock guarding other state, so no cross-counter ordering is needed.
#[derive(Debug, Default)]
pub struct CircuitMetrics {
	circuits_offered: AtomicU64,
	circuits_accepted: AtomicU64,
	circuits_rejected: AtomicU64,
	circuits_refused_at_capacity: AtomicU64,
	streams_served: AtomicU64,
	streams_rejected: AtomicU64,
	streams_shutdown: AtomicU64,
	streams_refused_at_capacity: AtomicU64,
}

impl CircuitMetrics {
	pub fn record_circuit_offered(&self) {
		self.circuits_offered.fetch_add(1, Ordering::Relaxed);
	}

	pub fn record_circuit_accepted(&self) {
		self.circuits_accepted.fetch_add(1, Ordering::Relaxed);
	}

	/// A stream was refused because the host-global concurrent-stream limit was full.
	pub fn record_stream_refused_at_capacity(&self) {
		self.streams_refused_at_capacity.fetch_add(1, Ordering::Relaxed);
	}

	/// A circuit was refused because the host-global concurrency limit was full.
	pub fn record_circuit_refused_at_capacity(&self) {
		self.circuits_refused_at_capacity.fetch_add(1, Ordering::Relaxed);
	}

	pub fn record_circuit_rejected(&self) {
		self.circuits_rejected.fetch_add(1, Ordering::Relaxed);
	}

	/// Record the outcome of the per-stream policy gate against the matching counter, so
	/// the loop increments through one tested mapping rather than three scattered calls.
	pub fn record_stream(&self, disposition: circuit_gate::StreamDisposition) {
		let counter = match disposition {
			circuit_gate::StreamDisposition::Serve => &self.streams_served,
			circuit_gate::StreamDisposition::Reject => &self.streams_rejected,
			circuit_gate::StreamDisposition::Shutdown => &self.streams_shutdown,
		};
		counter.fetch_add(1, Ordering::Relaxed);
	}

	pub fn snapshot(&self) -> ServiceMetrics {
		ServiceMetrics {
			circuits_offered: self.circuits_offered.load(Ordering::Relaxed),
			circuits_accepted: self.circuits_accepted.load(Ordering::Relaxed),
			circuits_rejected: self.circuits_rejected.load(Ordering::Relaxed),
			circuits_refused_at_capacity: self.circuits_refused_at_capacity.load(Ordering::Relaxed),
			streams_served: self.streams_served.load(Ordering::Relaxed),
			streams_rejected: self.streams_rejected.load(Ordering::Relaxed),
			streams_shutdown: self.streams_shutdown.load(Ordering::Relaxed),
			streams_refused_at_capacity: self.streams_refused_at_capacity.load(Ordering::Relaxed),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{OnionAddress, circuit_gate};

	#[test]
	fn circuit_metrics_snapshot_reflects_recorded_events() {
		use circuit_gate::StreamDisposition;
		let m = CircuitMetrics::default();
		assert_eq!(m.snapshot(), ServiceMetrics::default(), "a fresh counter set is all zeros");

		m.record_circuit_offered();
		m.record_circuit_offered();
		m.record_circuit_accepted();
		m.record_circuit_rejected();
		m.record_stream(StreamDisposition::Serve);
		m.record_stream(StreamDisposition::Serve);
		m.record_stream(StreamDisposition::Reject);
		m.record_stream(StreamDisposition::Shutdown);

		let snap = m.snapshot();
		assert_eq!(snap.circuits_offered, 2);
		assert_eq!(snap.circuits_accepted, 1);
		assert_eq!(snap.circuits_rejected, 1);
		assert_eq!(snap.streams_served, 2);
		assert_eq!(snap.streams_rejected, 1);
		assert_eq!(snap.streams_shutdown, 1);
	}

	#[test]
	fn record_stream_maps_each_disposition_to_its_own_counter() {
		use circuit_gate::StreamDisposition::{Reject, Serve, Shutdown};

		// Each disposition bumps exactly one distinct stream counter and never a circuit
		// counter. `pick` returns the per-disposition target counter; a helper records one
		// event and asserts only that counter (and no circuit counter) moved.
		let served = |s: ServiceMetrics| s.streams_served;
		let rejected = |s: ServiceMetrics| s.streams_rejected;
		let shutdown = |s: ServiceMetrics| s.streams_shutdown;
		let check = |disposition: circuit_gate::StreamDisposition, pick: &dyn Fn(ServiceMetrics) -> u64| {
			let m = CircuitMetrics::default();
			m.record_stream(disposition);
			let snap = m.snapshot();
			assert_eq!(pick(snap), 1, "{disposition:?} should bump its own counter");
			assert_eq!(snap.streams_served + snap.streams_rejected + snap.streams_shutdown, 1, "exactly one stream counter moves");
			assert_eq!(snap.circuits_offered + snap.circuits_accepted + snap.circuits_rejected, 0, "stream events never touch circuit counters");
		};

		check(Serve, &served);
		check(Reject, &rejected);
		check(Shutdown, &shutdown);
	}

	#[test]
	fn service_metrics_since_is_a_saturating_per_field_delta() {
		let earlier = ServiceMetrics {
			circuits_offered: 10,
			circuits_accepted: 7,
			circuits_rejected: 3,
			circuits_refused_at_capacity: 2,
			streams_served: 20,
			streams_rejected: 4,
			streams_shutdown: 1,
			streams_refused_at_capacity: 3,
		};
		let later = ServiceMetrics {
			circuits_offered: 15,
			circuits_accepted: 10,
			circuits_rejected: 5,
			circuits_refused_at_capacity: 6,
			streams_served: 26,
			streams_rejected: 4,
			streams_shutdown: 2,
			streams_refused_at_capacity: 9,
		};

		// The interval delta is the per-field difference.
		let delta = later.since(earlier);
		assert_eq!(
			delta,
			ServiceMetrics {
				circuits_offered: 5,
				circuits_accepted: 3,
				circuits_rejected: 2,
				circuits_refused_at_capacity: 4,
				streams_served: 6,
				streams_rejected: 0,
				streams_shutdown: 1,
				streams_refused_at_capacity: 6
			}
		);

		// Swapped operands saturate to zero rather than underflow-panicking.
		assert_eq!(earlier.since(later), ServiceMetrics::default());
		// A snapshot minus itself is no activity.
		assert_eq!(later.since(later), ServiceMetrics::default());
	}

	#[test]
	fn circuits_failed_transport_is_the_offered_minus_gated_remainder() {
		// offered − (accepted + rejected): the offers arti couldn't accept for transport
		// reasons, neither served nor a policy decision.
		let m = ServiceMetrics { circuits_offered: 20, circuits_accepted: 12, circuits_rejected: 5, ..Default::default() };
		assert_eq!(m.circuits_failed_transport(), 3);

		// Fully accounted-for offers → no transport failures.
		let settled = ServiceMetrics { circuits_offered: 10, circuits_accepted: 7, circuits_rejected: 3, ..Default::default() };
		assert_eq!(settled.circuits_failed_transport(), 0);

		// A torn read where accepted+rejected momentarily exceeds offered saturates, never underflows.
		let torn = ServiceMetrics { circuits_offered: 4, circuits_accepted: 3, circuits_rejected: 3, ..Default::default() };
		assert_eq!(torn.circuits_failed_transport(), 0);
	}

	#[test]
	fn total_streams_sums_every_disposition() {
		let m = ServiceMetrics { streams_served: 26, streams_rejected: 4, streams_shutdown: 2, ..Default::default() };
		assert_eq!(m.total_streams(), 32);
		assert_eq!(ServiceMetrics::default().total_streams(), 0);
	}

	#[test]
	fn to_prometheus_renders_all_eight_counters_in_exposition_format() {
		let m = ServiceMetrics {
			circuits_offered: 15,
			circuits_accepted: 10,
			circuits_rejected: 5,
			circuits_refused_at_capacity: 3,
			streams_served: 26,
			streams_rejected: 4,
			streams_shutdown: 2,
			streams_refused_at_capacity: 9,
		};
		let text = m.to_prometheus();

		// One HELP + one TYPE + one value line per counter → exactly 24 lines, trailing newline.
		assert!(text.ends_with('\n'), "exposition format ends with a newline");
		assert_eq!(text.lines().count(), 24, "8 counters × (HELP, TYPE, value)");

		// Each counter appears as a typed counter carrying its snapshot value, unlabeled.
		for (name, value) in [("onyums_circuits_offered_total", 15), ("onyums_circuits_accepted_total", 10), ("onyums_circuits_rejected_total", 5), ("onyums_circuits_refused_at_capacity_total", 3), ("onyums_streams_served_total", 26), ("onyums_streams_rejected_total", 4), ("onyums_streams_shutdown_total", 2), ("onyums_streams_refused_at_capacity_total", 9)] {
			assert!(text.contains(&format!("# TYPE {name} counter\n")), "{name} declared as a counter");
			assert!(text.contains(&format!("\n{name} {value}\n")), "{name} carries value {value} with no label block");
		}
	}

	#[test]
	fn to_prometheus_default_is_all_zeros() {
		let text = ServiceMetrics::default().to_prometheus();
		// Every counter is present and zero — a scraped fresh service is well-formed, not empty.
		assert!(text.contains("\nonyums_circuits_offered_total 0\n"));
		assert!(text.contains("\nonyums_streams_shutdown_total 0\n"));
		assert_eq!(text.lines().count(), 24);
	}

	#[test]
	fn to_prometheus_labeled_attaches_and_escapes_labels() {
		let m = ServiceMetrics { circuits_offered: 7, ..Default::default() };
		let text = m.to_prometheus_labeled(&[("service", "abcd.onion"), ("tier", "edge")]);

		// Labels ride on the value line, comma-joined inside braces, in the given order.
		assert!(text.contains("onyums_circuits_offered_total{service=\"abcd.onion\",tier=\"edge\"} 7\n"), "labels attach to the value line:\n{text}");
		// HELP/TYPE lines stay label-free — labels belong only on the sample.
		assert!(text.contains("# TYPE onyums_circuits_offered_total counter\n"));
	}

	#[test]
	fn prometheus_label_values_are_escaped_per_the_format() {
		// Backslash, double-quote, and newline are the three characters the exposition
		// format requires escaping in a label value; everything else passes through.
		assert_eq!(escape_prometheus_label_value("plain"), "plain");
		assert_eq!(escape_prometheus_label_value(r"a\b"), r"a\\b");
		assert_eq!(escape_prometheus_label_value("a\"b"), "a\\\"b");
		assert_eq!(escape_prometheus_label_value("a\nb"), "a\\nb");

		// End to end: a hostile label value can't break out of the quoted string.
		let text = ServiceMetrics::default().to_prometheus_labeled(&[("service", "a\"b\\c")]);
		assert!(text.contains("{service=\"a\\\"b\\\\c\"}"), "escaped label survives into the sample line:\n{text}");
	}

	#[test]
	fn empty_labels_render_identically_to_the_unlabeled_export() {
		let m = ServiceMetrics { streams_served: 3, ..Default::default() };
		assert_eq!(m.to_prometheus_labeled(&[]), m.to_prometheus(), "an empty label slice yields bare metric lines");
	}

	#[test]
	fn service_metrics_prometheus_labels_every_series_with_the_onion_address() {
		// The handle-level convenience labels the whole exposition with `service="<addr>"`
		// so several services scrape into one `/metrics` body distinguishably. Verified on
		// the free helper so no running service is needed.
		let addr = OnionAddress::normalized("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
		let m = ServiceMetrics { circuits_offered: 9, streams_served: 4, ..Default::default() };
		let text = service_metrics_prometheus(m, &addr);

		let label = format!("{{service=\"{}\"}}", addr.as_str());
		assert!(text.contains(&format!("onyums_circuits_offered_total{label} 9\n")), "offered series is labeled:\n{text}");
		assert!(text.contains(&format!("onyums_streams_served_total{label} 4\n")), "served series is labeled:\n{text}");
		// Same as calling the labeled exporter directly with the address.
		assert_eq!(text, m.to_prometheus_labeled(&[("service", addr.as_str())]));
	}

	#[test]
	fn fleet_prometheus_emits_each_header_once_and_every_service_sample() {
		let a = ServiceMetrics { circuits_offered: 9, streams_served: 4, ..Default::default() };
		let b = ServiceMetrics { circuits_offered: 1, streams_served: 100, ..Default::default() };
		let text = fleet_prometheus([("aaa.onion", a), ("bbb.onion", b)]);

		// The whole point: HELP/TYPE metadata appears exactly once per metric family, even
		// though two services report — this is what raw concatenation would get wrong.
		for name in ["onyums_circuits_offered_total", "onyums_circuits_accepted_total", "onyums_circuits_rejected_total", "onyums_streams_served_total", "onyums_streams_rejected_total", "onyums_streams_shutdown_total"] {
			assert_eq!(text.matches(&format!("# TYPE {name} counter\n")).count(), 1, "{name} declared exactly once");
			assert_eq!(text.matches(&format!("# HELP {name} ")).count(), 1, "{name} HELP exactly once");
		}

		// Both services' samples are present, each under its own service label.
		assert!(text.contains("onyums_circuits_offered_total{service=\"aaa.onion\"} 9\n"), "service a offered:\n{text}");
		assert!(text.contains("onyums_circuits_offered_total{service=\"bbb.onion\"} 1\n"), "service b offered:\n{text}");
		assert!(text.contains("onyums_streams_served_total{service=\"aaa.onion\"} 4\n"));
		assert!(text.contains("onyums_streams_served_total{service=\"bbb.onion\"} 100\n"));

		// Each family's header precedes both of its samples (metadata-then-samples ordering).
		let type_pos = text.find("# TYPE onyums_circuits_offered_total").unwrap();
		let sample_a = text.find("onyums_circuits_offered_total{service=\"aaa.onion\"}").unwrap();
		assert!(type_pos < sample_a, "TYPE header precedes the sample");
	}

	#[test]
	fn fleet_prometheus_of_one_matches_the_single_service_export() {
		// A one-service fleet is exactly the labeled single-service exposition.
		let m = ServiceMetrics { circuits_offered: 7, ..Default::default() };
		assert_eq!(fleet_prometheus([("solo.onion", m)]), m.to_prometheus_labeled(&[("service", "solo.onion")]));
	}

	#[test]
	fn fleet_prometheus_of_nothing_is_empty() {
		let empty: [(&str, ServiceMetrics); 0] = [];
		assert_eq!(fleet_prometheus(empty), "");
	}
}
