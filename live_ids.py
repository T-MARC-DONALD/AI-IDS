import time
import threading
import queue
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff, TCP, IP, get_if_list, get_if_addr
from collections import defaultdict, deque
import smtplib
from email.mime.text import MIMEText

# Email config
EMAIL_SENDER = "sender@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECIPIENT = "receiver@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Model artefacts
MODEL_PATH = "ids_model.joblib"
SCALER_PATH = "scaler.joblib"
ENCODER_PATHS = {
    "protocol_type": "protocol_type_encoder.joblib",
    "service": "service_encoder.joblib",
    "flag": "flag_encoder.joblib",
}

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
encoders = {col: joblib.load(path) for col, path in ENCODER_PATHS.items()}

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

app = Flask(__name__, static_folder="static", template_folder="templates")

_sniff_lock = threading.Lock()
sniffing_enabled = False
selected_interface = None

packet_history = defaultdict(lambda: deque(maxlen=100))
live_events = queue.Queue(maxsize=200)


def safe_transform(encoder, value, default=-1):
    """Encode categorical values safely; use default for unseen labels."""
    try:
        return encoder.transform([value])[0]
    except Exception:
        print(f"[Encoder] Unknown label '{value}' - using default ({default})")
        return default


def preprocess_row(row):
    df = pd.DataFrame([row], columns=FEATURE_COLUMNS).copy()
    for col in ("protocol_type", "service", "flag"):
        df[col] = safe_transform(encoders[col], df.at[0, col])
    df = df.apply(pd.to_numeric, errors="coerce")
    return scaler.transform(df)


def extract_features(packet):
    features = {}
    features["duration"] = 0

    proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
    proto = packet[IP].proto if packet.haslayer(IP) else -1
    features["protocol_type"] = proto_map.get(proto, "other")

    has_tcp = packet.haslayer(TCP)
    features["service"] = "http" if has_tcp and packet[TCP].dport == 80 else "other"
    features["flag"] = "S" if has_tcp and packet[TCP].flags == "S" else "OTH"

    features["src_bytes"] = len(packet)
    features["dst_bytes"] = 0

    for field in (
        "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
        "logged_in", "num_compromised", "root_shell", "su_attempted",
        "num_root", "num_file_creations", "num_shells", "num_access_files",
        "num_outbound_cmds", "is_host_login", "is_guest_login",
    ):
        features[field] = 0

    dst_ip = packet[IP].dst if packet.haslayer(IP) else "127.0.0.1"
    packet_history[dst_ip].append(packet)
    recent = list(packet_history[dst_ip])
    n = max(len(recent), 1)

    features["count"] = n

    if has_tcp:
        cur_dport = packet[TCP].dport
        features["srv_count"] = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].dport == cur_dport)
        syn_count = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].flags == "S")
        features["serror_rate"] = syn_count / n
    else:
        features["srv_count"] = 0
        features["serror_rate"] = 0.0

    features["srv_serror_rate"] = features["serror_rate"]
    features["rerror_rate"] = 0.0
    features["srv_rerror_rate"] = 0.0
    features["same_srv_rate"] = features["srv_count"] / n
    features["diff_srv_rate"] = 1 - features["same_srv_rate"]
    features["srv_diff_host_rate"] = 0.0
    features["dst_host_count"] = n
    features["dst_host_srv_count"] = features["srv_count"]
    features["dst_host_same_srv_rate"] = features["same_srv_rate"]
    features["dst_host_diff_srv_rate"] = features["diff_srv_rate"]
    features["dst_host_same_src_port_rate"] = 0.0
    features["dst_host_srv_diff_host_rate"] = 0.0
    features["dst_host_serror_rate"] = features["serror_rate"]
    features["dst_host_srv_serror_rate"] = features["serror_rate"]
    features["dst_host_rerror_rate"] = 0.0
    features["dst_host_srv_rerror_rate"] = 0.0

    return features


def packet_handler(packet):
    try:
        row = extract_features(packet)
        X = preprocess_row(row)
        pred = int(model.predict(X)[0])

        event = {
            "ts": time.time(),
            "pred": pred,
            "src_bytes": row["src_bytes"],
            "service": row["service"],
            "src_ip": packet[IP].src if packet.haslayer(IP) else "unknown",
            "dst_ip": packet[IP].dst if packet.haslayer(IP) else "unknown",
            "protocol": row["protocol_type"],
            "flag": row["flag"],
            "alert": pred == 1,
        }

        if live_events.full():
            try:
                live_events.get_nowait()
            except queue.Empty:
                pass
        live_events.put(event)
        print(f"[Sniffer] {event}")

        if pred == 1:
            send_email_alert(
                subject="IDS Alert: Attack Detected",
                body=(
                    f"Time:    {time.ctime(event['ts'])}\n"
                    f"Service: {event['service']}\n"
                    f"Src IP:  {event['src_ip']}\n"
                    f"Bytes:   {event['src_bytes']}"
                ),
            )

    except Exception as exc:
        err_event = {"ts": time.time(), "error": str(exc)}
        if live_events.full():
            try:
                live_events.get_nowait()
            except queue.Empty:
                pass
        live_events.put(err_event)
        print(f"[Sniffer] Error processing packet: {exc}")


def get_active_interface():
    with _sniff_lock:
        if selected_interface:
            try:
                ip = get_if_addr(selected_interface)
            except Exception:
                ip = None
            print(f"[Sniffer] Using selected interface: {selected_interface} ({ip})")
            return selected_interface

    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                print(f"[Sniffer] Using interface: {iface} ({ip})")
                return iface
        except Exception:
            continue

    print("[Sniffer] No active interface found - defaulting to 'lo'")
    return "lo"


def send_email_alert(subject, body):
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECIPIENT
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("[Alert] Email sent.")
    except Exception as exc:
        print(f"[Alert] Failed to send email: {exc}")


def run_sniffer():
    print("[Sniffer] Ready.")
    while True:
        with _sniff_lock:
            active = sniffing_enabled
        if active:
            try:
                iface = get_active_interface()
                sniff(prn=packet_handler, iface=iface, store=False, timeout=5)
            except Exception as exc:
                print(f"[Sniffer] Error: {exc}")
        else:
            time.sleep(1)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict-file", methods=["POST"])
def predict_file():
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    df = pd.read_csv(request.files["file"], header=None)
    if df.shape[1] != len(FEATURE_COLUMNS):
        return jsonify({"error": f"CSV must have {len(FEATURE_COLUMNS)} features"}), 400

    df.columns = FEATURE_COLUMNS
    for col in ("protocol_type", "service", "flag"):
        df[col] = df[col].apply(lambda v: safe_transform(encoders[col], v))
    df = df.apply(pd.to_numeric, errors="coerce")

    preds = model.predict(scaler.transform(df))
    return jsonify({
        "n_samples": len(preds),
        "predictions_sample": preds.tolist()[:20],
    })


@app.route("/toggle-sniffing", methods=["POST"])
def toggle_sniffing():
    global sniffing_enabled
    with _sniff_lock:
        sniffing_enabled = not sniffing_enabled
        state = sniffing_enabled
    return jsonify({"sniffing": state})


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


@app.route("/predict-single", methods=["POST"])
def predict_single():
    data = request.get_json()
    if not data or "sample" not in data:
        return jsonify({"error": "missing sample"}), 400

    parts = [p.strip() for p in data["sample"].split(",")]
    if len(parts) != len(FEATURE_COLUMNS):
        return jsonify({"error": f"expected {len(FEATURE_COLUMNS)} features, got {len(parts)}"}), 400

    df = pd.DataFrame([parts], columns=FEATURE_COLUMNS)
    for col in ("protocol_type", "service", "flag"):
        df[col] = safe_transform(encoders[col], df.at[0, col])

    X = scaler.transform(df.apply(pd.to_numeric, errors="coerce"))
    pred = int(model.predict(X)[0])
    return jsonify({"prediction": pred, "label": "Attack" if pred == 1 else "Normal"})


@app.route("/live-status")
def live_status():
    items = []
    tmp = queue.Queue()

    while True:
        try:
            item = live_events.get_nowait()
            items.append(item)
            tmp.put_nowait(item)
        except queue.Empty:
            break

    while True:
        try:
            live_events.put_nowait(tmp.get_nowait())
        except (queue.Empty, queue.Full):
            break

    summary = {
        "total": len(items),
        "normal": sum(1 for i in items if i.get("pred") == 0),
        "attack": sum(1 for i in items if i.get("pred") == 1),
    }
    return jsonify({"summary": summary, "recent": items[-20:]})


if __name__ == "__main__":
    t_sniff = threading.Thread(target=run_sniffer, daemon=True)
    t_sniff.start()
    app.run(debug=True)
