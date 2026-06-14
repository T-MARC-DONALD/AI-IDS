"""
flow_table.py

Stage 3: FlowTable class.

Manages a dictionary of active FlowRecord objects keyed by a normalized
5-tuple. Handles:
  - Direction normalization (same flow regardless of which side sent
    the first packet)
  - Adding packets to the right flow (creating new ones as needed)
  - Sweeping for expired flows (no packet for ACTIVITY_TIMEOUT seconds)
  - Computing features for expired flows and running them through the
    trained binary -> multiclass model pipeline

Usage (standalone test at bottom):
    python flow_table.py
"""

import threading
import time
import os
import warnings

import joblib
import pandas as pd
from scapy.all import IP, TCP, UDP
import sklearn
from sklearn.exceptions import InconsistentVersionWarning

from flow_record import FlowRecord


MODELS_DIR = "./models"


def _raise_if_version_mismatch(version_warnings, models_dir):
    if not version_warnings:
        return

    trained_versions = sorted({
        getattr(warning.message, "original_sklearn_version", None)
        for warning in version_warnings
        if getattr(warning.message, "original_sklearn_version", None)
    })
    trained_versions_text = ", ".join(trained_versions) if trained_versions else "unknown"
    current_version = getattr(sklearn, "__version__", "unknown")

    raise RuntimeError(
        "Model artifacts in "
        f"{models_dir} were trained with scikit-learn {trained_versions_text}, "
        f"but the current interpreter is using scikit-learn {current_version}. "
        "Run the app with a project virtual environment that has the matching "
        "dependencies installed or install the matching "
        "scikit-learn version before loading the saved models."
    )


# ----------------------------------------------------------------------
# Model loading / prediction (mirrors 05_validate_artifacts.py)
# ----------------------------------------------------------------------

def load_artifacts(models_dir=MODELS_DIR):
    artifacts = {}
    version_warnings = []
    for name in [
        "binary_model", "binary_scaler",
        "multiclass_model", "multiclass_scaler", "multiclass_label_encoder",
        "feature_columns",
    ]:
        path = os.path.join(models_dir, f"{name}.joblib")
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always", InconsistentVersionWarning)
            artifacts[name] = joblib.load(path)
        version_warnings.extend(
            warning
            for warning in caught_warnings
            if issubclass(warning.category, InconsistentVersionWarning)
        )

    _raise_if_version_mismatch(version_warnings, models_dir)

    # Force single-threaded prediction (see 05_validate_artifacts.py notes -
    # n_jobs=-1 adds ~70ms multiprocessing overhead per single-row predict)
    artifacts["binary_model"].n_jobs = 1
    artifacts["multiclass_model"].n_jobs = 1

    return artifacts


def predict_flow(feature_dict, artifacts):
    """
    feature_dict: dict of feature_name -> value (from FlowRecord.compute_features())

    Returns: (binary_label, attack_type_or_None)
    """
    feature_cols = artifacts["feature_columns"]
    row = pd.Series(feature_dict)

    # Defensive: clean inf/nan that could arise from edge-case flows
    # (e.g. zero-duration flows). Replace with 0 - matches the philosophy
    # of dropping such rows during training (rather than letting the model
    # see undefined values).
    row = row.replace([float("inf"), float("-inf")], 0.0).fillna(0.0)

    x = row.reindex(feature_cols).to_frame().T

    x_scaled = artifacts["binary_scaler"].transform(x)
    binary_pred = artifacts["binary_model"].predict(x_scaled)[0]

    if binary_pred == "BENIGN":
        return binary_pred, None

    x_scaled_mc = artifacts["multiclass_scaler"].transform(x)
    mc_pred_encoded = artifacts["multiclass_model"].predict(x_scaled_mc)[0]
    attack_type = artifacts["multiclass_label_encoder"].inverse_transform([mc_pred_encoded])[0]

    return binary_pred, attack_type


# ----------------------------------------------------------------------
# Flow key normalization
# ----------------------------------------------------------------------

def get_packet_5tuple(pkt):
    """
    Extract (src_ip, src_port, dst_ip, dst_port, protocol) from a packet.
    Returns None if the packet isn't IP+TCP/UDP.
    """
    if IP not in pkt:
        return None

    ip_layer = pkt[IP]
    proto = ip_layer.proto  # 6=TCP, 17=UDP

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    return (ip_layer.src, sport, ip_layer.dst, dport, proto)


def get_flow_lookup_keys(five_tuple):
    """
    Given a packet's 5-tuple (src_ip, src_port, dst_ip, dst_port, proto),
    return both possible canonical keys this packet could match:
      - fwd_key: assumes THIS packet's direction is the flow's "forward"
                 direction (i.e. this packet's sender started the flow)
      - bwd_key: assumes this packet is a REPLY to a flow that was
                 started in the opposite direction

    The FlowTable checks bwd_key first (does an existing flow already
    treat this packet's sender as the "backward" side?); if not found,
    it falls back to fwd_key, creating a new flow with THIS packet's
    sender as the forward side.

    This correctly handles "first packet seen defines forward direction"
    without relying on IP/port lexicographic ordering.
    """
    src_ip, src_port, dst_ip, dst_port, proto = five_tuple

    # If a flow already exists with (dst_ip,dst_port) as its forward source
    # and (src_ip,src_port) as its forward destination, this packet is the
    # reply (bwd) to that flow.
    bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)

    # Otherwise, this packet defines (or continues) a flow where it is fwd.
    fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)

    return fwd_key, bwd_key


# ----------------------------------------------------------------------
# FlowTable
# ----------------------------------------------------------------------

class FlowTable:
    """
    Thread-safe table of active flows. Call add_packet() for each captured
    packet, and sweep_expired() periodically (e.g. from a background thread)
    to close out idle flows, classify them, and remove them from the table.
    """

    def __init__(self, artifacts=None, on_flow_classified=None):
        self._flows = {}  # key -> FlowRecord
        self._lock = threading.Lock()
        self.artifacts = artifacts
        # Callback: on_flow_classified(flow_key, features, binary_label, attack_type)
        self.on_flow_classified = on_flow_classified

    def add_packet(self, pkt, pkt_time=None):
        """
        Add a packet to the appropriate flow, creating a new flow if needed.
        pkt_time: epoch seconds (float). If None, uses pkt.time (Scapy sniff
        timestamp) or falls back to time.time().
        """
        five_tuple = get_packet_5tuple(pkt)
        if five_tuple is None:
            return  # not IP+TCP/UDP, skip

        if pkt_time is None:
            pkt_time = float(getattr(pkt, "time", time.time()))

        fwd_key, bwd_key = get_flow_lookup_keys(five_tuple)

        with self._lock:
            if bwd_key in self._flows:
                # An existing flow treats this packet's sender as its
                # "backward" side - this packet is a reply.
                key, direction = bwd_key, "bwd"
            elif fwd_key in self._flows:
                # An existing flow already has this packet's sender as
                # forward - continue in that direction.
                key, direction = fwd_key, "fwd"
            else:
                # New flow - this packet's sender defines the forward
                # direction.
                key, direction = fwd_key, "fwd"
                src_ip, src_port, dst_ip, dst_port, proto = key
                self._flows[key] = FlowRecord(
                    src_ip=src_ip, src_port=src_port,
                    dst_ip=dst_ip, dst_port=dst_port,
                    protocol=proto, first_pkt_time=pkt_time,
                )

            self._flows[key].add_packet(pkt, pkt_time, direction)

    def sweep_expired(self, now=None):
        """
        Find flows that have been idle longer than ACTIVITY_TIMEOUT,
        compute their features, classify them, call the callback, and
        remove them from the table.

        Returns a list of (flow_key, features, binary_label, attack_type)
        for the expired flows processed in this sweep.
        """
        if now is None:
            now = time.time()

        results = []

        with self._lock:
            expired_keys = [
                key for key, flow in self._flows.items()
                if flow.is_expired(now)
            ]

            for key in expired_keys:
                flow = self._flows.pop(key)
                features = flow.compute_features()

                binary_label, attack_type = (None, None)
                if self.artifacts is not None:
                    binary_label, attack_type = predict_flow(features, self.artifacts)

                results.append((key, features, binary_label, attack_type))

        # Fire callbacks outside the lock to avoid holding it during
        # potentially slow operations (e.g. email alerts in live_ids.py)
        for key, features, binary_label, attack_type in results:
            if self.on_flow_classified is not None:
                self.on_flow_classified(key, features, binary_label, attack_type)

        return results

    def active_flow_count(self):
        with self._lock:
            return len(self._flows)

    def force_expire_all(self, now=None):
        """
        Force-expire ALL flows regardless of timeout. Useful for shutdown
        or for processing the tail end of a finite packet capture (e.g. a
        PCAP file) where flows never naturally time out.
        """
        if now is None:
            now = time.time()

        results = []
        with self._lock:
            keys = list(self._flows.keys())
            for key in keys:
                flow = self._flows.pop(key)
                features = flow.compute_features()

                binary_label, attack_type = (None, None)
                if self.artifacts is not None:
                    binary_label, attack_type = predict_flow(features, self.artifacts)

                results.append((key, features, binary_label, attack_type))

        for key, features, binary_label, attack_type in results:
            if self.on_flow_classified is not None:
                self.on_flow_classified(key, features, binary_label, attack_type)

        return results


# ----------------------------------------------------------------------
# Background sweeper thread
# ----------------------------------------------------------------------

class FlowSweeper(threading.Thread):
    """
    Periodically calls flow_table.sweep_expired(). Run as a daemon thread
    alongside the Scapy sniffer.
    """

    def __init__(self, flow_table, interval=5.0):
        super().__init__(daemon=True)
        self.flow_table = flow_table
        self.interval = interval
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            self.flow_table.sweep_expired()
            self._stop_event.wait(self.interval)

    def stop(self):
        self._stop_event.set()


# ----------------------------------------------------------------------
# Standalone test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from scapy.all import Ether

    print("Loading model artifacts...")
    try:
        artifacts = load_artifacts()
        print("Artifacts loaded.\n")
    except FileNotFoundError as e:
        print(f"Could not load artifacts ({e}). Running without classification.\n")
        artifacts = None

    results_log = []

    def on_classified(key, features, binary_label, attack_type):
        results_log.append((key, binary_label, attack_type))
        src_ip, src_port, dst_ip, dst_port, proto = key
        label_str = binary_label or "?"
        type_str = f" ({attack_type})" if attack_type else ""
        print(f"Flow expired: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} "
              f"proto={proto} -> {label_str}{type_str}  "
              f"[{features['Total Fwd Packets']} fwd / "
              f"{features['Total Backward Packets']} bwd pkts] "
              f"(Flow A expects 6 fwd/1 bwd, Flow B expects 1 fwd/1 bwd)")

    table = FlowTable(artifacts=artifacts, on_flow_classified=on_classified)

    print("=" * 60)
    print("Test 1: Two separate flows, packets interleaved")
    print("=" * 60)

    # Flow A: client 10.0.0.5:50000 <-> server 10.0.0.10:80
    # Flow B: client 10.0.0.6:51000 <-> server 10.0.0.20:443
    base_t = 5000.0

    # Flow A - forward SYN
    pkt = (Ether() / IP(src="10.0.0.5", dst="10.0.0.10") /
           TCP(sport=50000, dport=80, flags="S", dataofs=5, window=29200))
    table.add_packet(pkt, base_t)

    # Flow B - forward SYN
    pkt = (Ether() / IP(src="10.0.0.6", dst="10.0.0.20") /
           TCP(sport=51000, dport=443, flags="S", dataofs=5, window=29200))
    table.add_packet(pkt, base_t + 0.01)

    # Flow A - backward SYN-ACK (note: src/dst swapped vs first packet)
    pkt = (Ether() / IP(src="10.0.0.10", dst="10.0.0.5") /
           TCP(sport=80, dport=50000, flags="SA", dataofs=5, window=64240))
    table.add_packet(pkt, base_t + 0.02)

    # Flow A - forward ACK + data, several packets
    for i in range(5):
        pkt = (Ether() / IP(src="10.0.0.5", dst="10.0.0.10") /
               TCP(sport=50000, dport=80, flags="PA", dataofs=5, window=29200) /
               (b"X" * 200))
        table.add_packet(pkt, base_t + 0.03 + i * 0.01)

    # Flow B - backward SYN-ACK
    pkt = (Ether() / IP(src="10.0.0.20", dst="10.0.0.6") /
           TCP(sport=443, dport=51000, flags="SA", dataofs=5, window=64240))
    table.add_packet(pkt, base_t + 0.02)

    print(f"\nActive flows in table: {table.active_flow_count()} (expected 2)")

    print("\n" + "=" * 60)
    print("Test 2: Force-expire all flows and classify")
    print("=" * 60)

    expired = table.force_expire_all(now=base_t + 1000)  # well past timeout
    print(f"\nFlows expired and processed: {len(expired)} (expected 2)")
    print(f"Active flows remaining: {table.active_flow_count()} (expected 0)")

    print("\n" + "=" * 60)
    print("Test 3: Direction normalization check")
    print("=" * 60)
    print("Verifying both flows were keyed consistently regardless of")
    print("which packet (fwd or bwd) arrived first for the 5-tuple...")
    for key, binary_label, attack_type in results_log:
        src_ip, src_port, dst_ip, dst_port, proto = key
        print(f"  Key: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} -> {binary_label} {attack_type or ''}")

    print("\nDone.")
