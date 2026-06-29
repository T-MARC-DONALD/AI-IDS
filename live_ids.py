"""
live_ids.py

Flow-based real-time IDS using:
  - Scapy for packet capture
  - FlowTable / FlowSweeper for CICFlowMeter-style flow assembly
    (see flow_record.py, flow_table.py)
  - A two-stage RandomForest pipeline (binary BENIGN/ATTACK, then
    multiclass attack-type) trained on CIC-IDS2017

Architecture changes from the previous NSL-KDD per-packet version:
  - Classification happens per FLOW (at flow expiry), not per packet.
  - Each flow produces both a binary verdict and (if ATTACK) an
    attack-type label.
  - live_events is a deque + lock (not a Queue) - fixes the race
    condition where events were lost/duplicated between /live-status polls.
  - The sniffer loop checks sniffing_enabled OUTSIDE the lock before
    calling get_active_interface(), which also acquires the lock -
    fixes a potential deadlock.
  - Email/SMTP credentials and tunables are read from environment
    variables (.env via python-dotenv), not hardcoded.

Run:
    pip install -r requirements.txt
    cp .env.example .env   # then edit .env with real values
    python live_ids.py
"""

import os
import time
import threading
from collections import deque

import pandas as pd
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff, get_if_list, get_if_addr

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*args, **kwargs):
        return False

from alerting import AlertManager
from flow_table import FlowTable, FlowSweeper, load_artifacts


# ----------------------------------------------------------------------
# Configuration (from .env / environment)
# ----------------------------------------------------------------------

if not load_dotenv():
    print("[Config] python-dotenv not installed or no .env file found - using process environment only.")

MODELS_DIR = os.environ.get("MODELS_DIR", "./models")
FLOW_ACTIVITY_TIMEOUT = float(os.environ.get("FLOW_ACTIVITY_TIMEOUT", "120"))
FLOW_SWEEP_INTERVAL = float(os.environ.get("FLOW_SWEEP_INTERVAL", "5"))
APP_DEBUG = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}

alert_manager = AlertManager(os.environ)
if alert_manager.has_external_channels:
    print(f"[Config] Alert channels armed: {', '.join(alert_manager.enabled_labels())}")
else:
    print("[Config] No external alert channels configured - alerts will be logged only.")


# ----------------------------------------------------------------------
# Load model artifacts
# ----------------------------------------------------------------------

print(f"[Startup] Loading model artifacts from {MODELS_DIR} ...")
try:
    artifacts = load_artifacts(MODELS_DIR)
except RuntimeError as exc:
    print(f"[Startup] {exc}")
    raise SystemExit(1) from exc
print("[Startup] Artifacts loaded.")


# ----------------------------------------------------------------------
# Global state
# ----------------------------------------------------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

_sniff_lock = threading.Lock()
_stats_lock = threading.Lock()
sniffing_enabled = False
selected_interface = None
_last_logged_interface = None

# Cumulative stats
packet_total = 0
flow_total = 0
benign_total = 0
attack_total = 0
last_event_ts = None
last_attack_ts = None
last_attack_src_ip = None
last_attack_type = None

# Recent classified flows for the dashboard.
# Fixed-size deque + lock (replaces the buggy Queue-based live_events,
# which lost/duplicated events between /live-status polls because it
# was drained and refilled on every request).
EVENTS_MAXLEN = 200
live_events = deque(maxlen=EVENTS_MAXLEN)
_events_lock = threading.Lock()

# FlowTable.ACTIVITY_TIMEOUT is a class attribute on FlowRecord; apply the
# configured value to all new FlowRecords via FlowTable's flows.
import flow_record  # noqa: E402  (import after config so override applies)
flow_record.FlowRecord.ACTIVITY_TIMEOUT = FLOW_ACTIVITY_TIMEOUT


# ----------------------------------------------------------------------
# Flow classification callback
# ----------------------------------------------------------------------

def on_flow_classified(flow_key, features, binary_label, attack_type):
    """
    Called by FlowSweeper for each flow that has expired and been
    classified. Updates stats, pushes an event for the dashboard, and
    fires alert notifications for ATTACK flows.
    """
    global flow_total, benign_total, attack_total
    global last_event_ts, last_attack_ts, last_attack_src_ip, last_attack_type

    src_ip, src_port, dst_ip, dst_port, proto = flow_key
    proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
    now = time.time()

    event = {
        "ts": now,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto_name,
        "binary_label": binary_label,
        "attack_type": attack_type,
        "alert": binary_label == "ATTACK",
        "total_fwd_packets": features.get("Total Fwd Packets"),
        "total_bwd_packets": features.get("Total Backward Packets"),
        "flow_duration_us": features.get("Flow Duration"),
        "flow_bytes_per_s": features.get("Flow Bytes/s"),
        "features": features,
    }

    with _stats_lock:
        flow_total += 1
        last_event_ts = now
        if binary_label == "BENIGN":
            benign_total += 1
        else:
            attack_total += 1
            last_attack_ts = now
            last_attack_src_ip = src_ip
            last_attack_type = attack_type

    with _events_lock:
        live_events.append(event)

    print(f"[Flow] {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto_name}) "
          f"=> {binary_label}" + (f" ({attack_type})" if attack_type else ""))

    if binary_label == "ATTACK":
        alert_manager.send_attack_alert_async(event)


# ----------------------------------------------------------------------
# Flow table + sweeper
# ----------------------------------------------------------------------

flow_table = FlowTable(artifacts=artifacts, on_flow_classified=on_flow_classified)
flow_sweeper = FlowSweeper(flow_table, interval=FLOW_SWEEP_INTERVAL)


def normalize_feature_frame(df):
    feature_cols = list(artifacts["feature_columns"])

    frame = df.copy()
    frame.columns = [str(col).strip() for col in frame.columns]
    if not set(feature_cols).issubset(set(frame.columns)):
        if frame.shape[1] == len(feature_cols):
            frame.columns = feature_cols
        else:
            raise ValueError(
                f"input does not match expected feature schema "
                f"({len(feature_cols)} features required, got {frame.shape[1]})"
            )

    frame = frame[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    return frame.replace([float("inf"), float("-inf")], 0.0)


def predict_feature_frame(df):
    frame = normalize_feature_frame(df)

    chunk_size = 5000
    predictions = []

    binary_model = artifacts["binary_model"]
    binary_scaler = artifacts["binary_scaler"]
    multiclass_model = artifacts["multiclass_model"]
    multiclass_scaler = artifacts["multiclass_scaler"]
    label_encoder = artifacts["multiclass_label_encoder"]

    for start in range(0, len(frame), chunk_size):
        chunk = frame.iloc[start:start + chunk_size]

        chunk_scaled = binary_scaler.transform(chunk)
        chunk_binary = binary_model.predict(chunk_scaled)

        chunk_types = [None] * len(chunk)
        attack_mask = chunk_binary == "ATTACK"
        if attack_mask.any():
            attack_rows = chunk[attack_mask]
            attack_scaled = multiclass_scaler.transform(attack_rows)
            mc_pred = multiclass_model.predict(attack_scaled)
            mc_labels = label_encoder.inverse_transform(mc_pred)
            attack_indices = [index for index, is_attack in enumerate(attack_mask) if is_attack]
            for idx, label in zip(attack_indices, mc_labels):
                chunk_types[idx] = label

        predictions.extend(
            {"binary": binary, "attack_type": attack_type}
            for binary, attack_type in zip(chunk_binary.tolist(), chunk_types)
        )

    return predictions


# ----------------------------------------------------------------------
# Packet capture
# ----------------------------------------------------------------------

def packet_handler(packet):
    global packet_total

    with _stats_lock:
        packet_total += 1

    try:
        flow_table.add_packet(packet)
    except Exception as exc:
        print(f"[Sniffer] Error processing packet: {exc}")


def get_active_interface():
    """
    Returns the interface to sniff on. Does NOT acquire _sniff_lock itself
    for the fallback scan - callers that already hold the lock should read
    `selected_interface` directly instead of calling this while holding it.
    This function is intended to be called WITHOUT _sniff_lock held.
    """
    with _sniff_lock:
        iface = selected_interface

    global _last_logged_interface

    if iface:
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = None
        current = ("selected", iface, ip)
        if current != _last_logged_interface:
            print(f"[Sniffer] Using selected interface: {iface} ({ip})")
            _last_logged_interface = current
        return iface

    for candidate in get_if_list():
        try:
            ip = get_if_addr(candidate)
            if ip and ip != "0.0.0.0":
                current = ("auto", candidate, ip)
                if current != _last_logged_interface:
                    print(f"[Sniffer] Using interface: {candidate} ({ip})")
                    _last_logged_interface = current
                return candidate
        except Exception:
            continue

    print("[Sniffer] No active interface found - defaulting to 'lo'")
    return "lo"


def run_sniffer():
    """
    Background sniffer loop.

    BUGFIX: previously this checked `sniffing_enabled` while holding
    `_sniff_lock`, then called `get_active_interface()` which ALSO tried
    to acquire `_sniff_lock` - a deadlock with a non-reentrant Lock.
    Now the lock is released before calling get_active_interface().
    """
    print("[Sniffer] Ready.")
    while True:
        with _sniff_lock:
            active = sniffing_enabled
        if active:
            try:
                iface = get_active_interface()  # lock released above
                sniff(prn=packet_handler, iface=iface, store=False, timeout=5)
            except Exception as exc:
                print(f"[Sniffer] Error: {exc}")
        else:
            time.sleep(1)


# ----------------------------------------------------------------------
# Flask routes
# ----------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/alerts")
def alerts_page():
    alert_snapshot = alert_manager.snapshot()
    return render_template(
        "alerts.html",
        alert_channels=alert_snapshot["channels"],
        alert_summary=alert_snapshot["summary"],
    )


@app.route("/alerts/test", methods=["POST"])
def test_alert_channels():
    data = request.get_json() or {}
    channel = str(data.get("channel", "all")).strip() or "all"
    results = alert_manager.send_test_alert(channel_keys=[channel])
    return jsonify({
        "results": results,
        "alerts": alert_manager.snapshot(),
    })


@app.route("/alerts/configure", methods=["POST"])
def configure_alert_channel():
    data = request.get_json() or {}
    channel = str(data.get("channel", "")).strip()
    if not channel:
        return jsonify({"error": "missing channel"}), 400

    try:
        alerts = alert_manager.configure_channel(
            channel_key=channel,
            enabled=data.get("enabled"),
            settings=data.get("settings") or {},
        )
    except KeyError:
        return jsonify({"error": "unknown channel"}), 400

    return jsonify({"alerts": alerts})


@app.route("/alerts/telegram/discover", methods=["POST"])
def discover_telegram_chat():
    try:
        chat = alert_manager.discover_telegram_chat()
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(chat)


@app.route("/predict/csv")
def csv_prediction_page():
    return render_template("csv_prediction.html", feature_count=len(artifacts["feature_columns"]))


@app.route("/predict/sample")
def sample_prediction_page():
    feature_columns = list(artifacts["feature_columns"])
    return render_template(
        "sample_prediction.html",
        feature_columns=feature_columns,
        feature_count=len(feature_columns),
    )


@app.route("/toggle-sniffing", methods=["POST"])
def toggle_sniffing():
    global sniffing_enabled
    with _sniff_lock:
        sniffing_enabled = not sniffing_enabled
        state = sniffing_enabled

    flushed = 0
    if not state:
        flushed = len(flow_table.force_expire_all())

    if flushed:
        print(f"[Sniffer] Capture stopped - flushed {flushed} active flow(s) for immediate classification.")
    return jsonify({"sniffing": state, "flushed_flows": flushed})


@app.route("/interfaces")
def list_interfaces():
    res = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = None
        res.append({"iface": iface, "addr": ip})

    with _sniff_lock:
        cur = selected_interface
    return jsonify({"interfaces": res, "selected": cur})


@app.route("/set-interface", methods=["POST"])
def set_interface():
    data = request.get_json() or {}
    iface = data.get("iface")
    if not iface:
        return jsonify({"error": "missing iface"}), 400

    if iface not in get_if_list():
        return jsonify({"error": "unknown iface"}), 400

    global selected_interface
    with _sniff_lock:
        selected_interface = iface
    return jsonify({"selected": selected_interface})


@app.route("/predict-file", methods=["POST"])
def predict_file():
    """
    Batch-score a CSV of pre-computed flow features (78 CICFlowMeter-style
    columns, with header row matching feature_columns.joblib - or in the
    same column order, headerless).

    NOTE: this is for flow-feature CSVs (e.g. CIC-IDS2017-style exports),
    NOT raw packet captures. Use a tool like CICFlowMeter to produce flow
    CSVs from a PCAP first.
    """
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    try:
        df = pd.read_csv(request.files["file"])
    except Exception as exc:
        return jsonify({"error": f"could not read CSV: {exc}"}), 400

    try:
        predictions = predict_feature_frame(df)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    n_attack = sum(1 for prediction in predictions if prediction["binary"] == "ATTACK")
    return jsonify({
        "n_samples": len(predictions),
        "n_benign": len(predictions) - n_attack,
        "n_attack": n_attack,
        "predictions_sample": predictions[:20],
    })


@app.route("/predict-sample", methods=["POST"])
def predict_sample():
    data = request.get_json() or {}
    row_text = str(data.get("row", "")).strip()
    feature_columns = list(artifacts["feature_columns"])

    if not row_text:
        return jsonify({"error": "no feature row provided"}), 400

    values = [value.strip() for value in row_text.split(",")]
    if len(values) != len(feature_columns):
        return jsonify({
            "error": (
                f"expected {len(feature_columns)} comma-separated values, "
                f"received {len(values)}"
            )
        }), 400

    sample_df = pd.DataFrame([values], columns=feature_columns)

    try:
        prediction = predict_feature_frame(sample_df)[0]
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "n_features": len(feature_columns),
        "prediction": prediction,
    })


@app.route("/live-status")
def live_status():
    with _events_lock:
        items = list(live_events)

    with _stats_lock:
        totals = {
            "packets": packet_total,
            "total": flow_total,
            "benign": benign_total,
            "attack": attack_total,
            "last_event_ts": last_event_ts,
            "last_attack_ts": last_attack_ts,
            "last_attack_src_ip": last_attack_src_ip,
            "last_attack_type": last_attack_type,
        }

    with _sniff_lock:
        active = sniffing_enabled
        iface = selected_interface

    return jsonify({
        "summary": {
            "total": len(items),
            "benign": sum(1 for i in items if i.get("binary_label") == "BENIGN"),
            "attack": sum(1 for i in items if i.get("binary_label") == "ATTACK"),
        },
        "recent": items[-20:],
        "active_flows": flow_table.active_flow_count(),
        "sniffing": active,
        "interface": iface,
        "totals": totals,
        "alerts": alert_manager.snapshot(),
    })


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    t_sniff = threading.Thread(target=run_sniffer, daemon=True)
    t_sniff.start()

    flow_sweeper.start()

    app.run(debug=APP_DEBUG, use_reloader=APP_DEBUG)
