<<<<<<< HEAD
# live_ids.py
import time, threading, queue, joblib, pandas as pd
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff, TCP, UDP, IP
from scapy.all import get_if_list, get_if_addr
from threading import Thread
=======
# live_ids.py  — fixed edition
#
# Bugs fixed vs. original:
#   1.  Duplicate sniffer thread: Thread(target=run_sniffer).start() was called
#       twice (once via t_sniff, once via an anonymous Thread). Now called once.
#   2.  NameError in packet_handler: `pred` was referenced in the email-alert
#       block even when an exception had been raised before the prediction ran.
#       Restructured so the email path is only reachable after a successful pred.
#   3.  AttributeError in extract_features: `srv_count` and `serror_rate` used
#       packet[TCP] unconditionally even when the packet had no TCP layer.
#       Now guarded with haslayer(TCP).
#   4.  predict-file route skipped categorical encoding before calling
#       scaler.transform, causing a ValueError. Now uses preprocess_row().
#   5.  predict-single used bare encoder.transform instead of safe_transform,
#       crashing on unseen labels. Now uses safe_transform for all cat columns.
#   6.  sniffing_enabled toggled and read from two threads without a lock.
#       Now protected by a threading.Lock.
#   7.  live_events.queue iteration in /live-status was not thread-safe.
#       Now snapshotted safely.
#   8.  HTML table row had a broken </td> tag — src_ip column was missing.
#       Fixed in index.html.

import time
import threading
import queue
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
from scapy.all import sniff, TCP, UDP, IP, get_if_list, get_if_addr
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
from collections import defaultdict, deque
import smtplib
from email.mime.text import MIMEText

<<<<<<< HEAD
EMAIL_SENDER = "sender@gmail.com"
EMAIL_PASSWORD = "your password"
EMAIL_RECIPIENT = "reciever@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587



MODEL_PATH = 'ids_model.joblib'
SCALER_PATH = 'scaler.joblib'
ENCODER_PATHS = {
    'protocol_type': 'protocol_type_encoder.joblib',
    'service': 'service_encoder.joblib',
    'flag': 'flag_encoder.joblib'
}

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
encoders = {col: joblib.load(path) for col, path in ENCODER_PATHS.items()}

FEATURE_COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in','num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate'
=======
# ------------------------------------------------------------------ #
#  Email config                                                        #
# ------------------------------------------------------------------ #
EMAIL_SENDER    = "sender@gmail.com"
EMAIL_PASSWORD  = "your_app_password"
EMAIL_RECIPIENT = "receiver@gmail.com"
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 587

# ------------------------------------------------------------------ #
#  Model artefacts                                                     #
# ------------------------------------------------------------------ #
MODEL_PATH  = 'ids_model.joblib'
SCALER_PATH = 'scaler.joblib'
ENCODER_PATHS = {
    'protocol_type': 'protocol_type_encoder.joblib',
    'service':       'service_encoder.joblib',
    'flag':          'flag_encoder.joblib',
}

model    = joblib.load(MODEL_PATH)
scaler   = joblib.load(SCALER_PATH)
encoders = {col: joblib.load(path) for col, path in ENCODER_PATHS.items()}

FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate',
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
]

app = Flask(__name__, static_folder='static', template_folder='templates')

<<<<<<< HEAD
sniffing_enabled = False
packet_history = defaultdict(lambda: deque(maxlen=100))

# ---------------- Preprocessing ----------------
def safe_transform(encoder, value, default=-1):
    try:
        return encoder.transform([value])[0]
    except Exception as e:
=======
# FIX 6: protect sniffing_enabled with a lock
_sniff_lock      = threading.Lock()
sniffing_enabled = False
selected_interface = None

packet_history = defaultdict(lambda: deque(maxlen=100))

# ------------------------------------------------------------------ #
#  Preprocessing                                                       #
# ------------------------------------------------------------------ #

def safe_transform(encoder, value, default=-1):
    """Encode a single categorical value; return default for unseen labels."""
    try:
        return encoder.transform([value])[0]
    except Exception:
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
        print(f"[Encoder] Unknown label '{value}' — using default ({default})")
        return default


def preprocess_row(row):
<<<<<<< HEAD
    df = pd.DataFrame([row], columns=FEATURE_COLUMNS).copy()
    for col in ['protocol_type', 'service', 'flag']:
=======
    """Convert a feature dict into a scaled numpy array ready for predict."""
    df = pd.DataFrame([row], columns=FEATURE_COLUMNS).copy()
    for col in ('protocol_type', 'service', 'flag'):
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
        df[col] = safe_transform(encoders[col], df.at[0, col])
    df = df.apply(pd.to_numeric, errors='coerce')
    return scaler.transform(df)

<<<<<<< HEAD
# ---------------- Live IDS ----------------
pred_queue = queue.Queue()
live_events = queue.Queue(maxsize=200)

def extract_features(packet):
    features = {}
    features['duration'] = 0
    proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
    features['protocol_type'] = proto_map.get(packet.proto, 'other')
    features['service'] = 'http' if packet.haslayer(TCP) and packet[TCP].dport == 80 else 'other'
    features['flag'] = 'S' if packet.haslayer(TCP) and packet[TCP].flags == 'S' else 'OTH'
    features['src_bytes'] = len(packet)
    features['dst_bytes'] = 0
    features['land'] = 0
    features['wrong_fragment'] = 0
    features['urgent'] = 0
    features['hot'] = 0
    features['num_failed_logins'] = 0
    features['logged_in'] = 0
    features['num_compromised'] = 0
    features['root_shell'] = 0
    features['su_attempted'] = 0
    features['num_root'] = 0
    features['num_file_creations'] = 0
    features['num_shells'] = 0
    features['num_access_files'] = 0
    features['num_outbound_cmds'] = 0
    features['is_host_login'] = 0
    features['is_guest_login'] = 0

    dst_ip = packet[IP].dst if packet.haslayer(IP) else '127.0.0.1'
    packet_history[dst_ip].append(packet)

    recent = list(packet_history[dst_ip])
    features['count'] = len(recent)
    features['srv_count'] = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].dport == packet[TCP].dport)
    features['serror_rate'] = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].flags == 'S') / len(recent)
    features['srv_serror_rate'] = features['serror_rate']
    features['rerror_rate'] = 0
    features['srv_rerror_rate'] = 0
    features['same_srv_rate'] = features['srv_count'] / len(recent)
    features['diff_srv_rate'] = 1 - features['same_srv_rate']
    features['srv_diff_host_rate'] = 0
    features['dst_host_count'] = len(recent)
    features['dst_host_srv_count'] = features['srv_count']
    features['dst_host_same_srv_rate'] = features['same_srv_rate']
    features['dst_host_diff_srv_rate'] = features['diff_srv_rate']
    features['dst_host_same_src_port_rate'] = 0
    features['dst_host_srv_diff_host_rate'] = 0
    features['dst_host_serror_rate'] = features['serror_rate']
    features['dst_host_srv_serror_rate'] = features['serror_rate']
    features['dst_host_rerror_rate'] = 0
    features['dst_host_srv_rerror_rate'] = 0
=======

# ------------------------------------------------------------------ #
#  Live IDS                                                            #
# ------------------------------------------------------------------ #

live_events: "queue.Queue[dict]" = queue.Queue(maxsize=200)


def extract_features(packet):
    """Build an NSL-KDD-style feature dict from a scapy packet."""
    features = {}
    features['duration'] = 0

    proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
    features['protocol_type'] = proto_map.get(packet.proto, 'other')

    # FIX 3: guard all TCP-specific access
    has_tcp = packet.haslayer(TCP)
    features['service'] = 'http' if has_tcp and packet[TCP].dport == 80 else 'other'
    features['flag']    = 'S'   if has_tcp and packet[TCP].flags == 'S' else 'OTH'

    features['src_bytes'] = len(packet)
    features['dst_bytes'] = 0

    for f in ('land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
              'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
              'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
              'num_outbound_cmds', 'is_host_login', 'is_guest_login'):
        features[f] = 0

    dst_ip = packet[IP].dst if packet.haslayer(IP) else '127.0.0.1'
    packet_history[dst_ip].append(packet)
    recent = list(packet_history[dst_ip])
    n = len(recent)

    features['count'] = n

    if has_tcp:
        cur_dport             = packet[TCP].dport
        features['srv_count'] = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].dport == cur_dport)
        syn_count             = sum(1 for p in recent if p.haslayer(TCP) and p[TCP].flags == 'S')
        features['serror_rate'] = syn_count / n
    else:
        features['srv_count']   = 0
        features['serror_rate'] = 0.0

    features['srv_serror_rate']              = features['serror_rate']
    features['rerror_rate']                  = 0.0
    features['srv_rerror_rate']              = 0.0
    features['same_srv_rate']                = features['srv_count'] / n
    features['diff_srv_rate']                = 1 - features['same_srv_rate']
    features['srv_diff_host_rate']           = 0.0
    features['dst_host_count']               = n
    features['dst_host_srv_count']           = features['srv_count']
    features['dst_host_same_srv_rate']       = features['same_srv_rate']
    features['dst_host_diff_srv_rate']       = features['diff_srv_rate']
    features['dst_host_same_src_port_rate']  = 0.0
    features['dst_host_srv_diff_host_rate']  = 0.0
    features['dst_host_serror_rate']         = features['serror_rate']
    features['dst_host_srv_serror_rate']     = features['serror_rate']
    features['dst_host_rerror_rate']         = 0.0
    features['dst_host_srv_rerror_rate']     = 0.0
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)

    return features


def packet_handler(packet):
<<<<<<< HEAD
    try:
        row = extract_features(packet)
        X = preprocess_row(row)
        pred = model.predict(X)[0]
        event = {
            'ts': time.time(),
            'pred': int(pred),
            'src_bytes': row['src_bytes'],
            'service': row['service'],
            'src_ip': packet[IP].src if packet.haslayer(IP) else 'unknown',
            'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'unknown',
            'protocol': row['protocol_type'],
            'flag': row['flag'],
            'alert': pred == 1
        }
        if live_events.full():
            live_events.get()
        live_events.put(event)
        print(f"[Sniffer] Packet classified: {event}")
    except Exception as e:
        live_events.put({'ts': time.time(), 'error': str(e)})
        print(f"[Sniffer] Error processing packet: {e}")

    if pred == 1:
        event['alert'] = True
        send_email_alert(
            subject="🚨 IDS Alert: Attack Detected",
            body=f"Time: {time.ctime(event['ts'])}\nService: {event['service']}\nBytes: {event['src_bytes']}"
        )
    else:
        event['alert'] = False



def get_active_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            if ip != '0.0.0.0':
=======
    # FIX 2: restructured so pred is always defined before use;
    #        email only reached on successful prediction.
    try:
        row  = extract_features(packet)
        X    = preprocess_row(row)
        pred = int(model.predict(X)[0])

        event = {
            'ts':        time.time(),
            'pred':      pred,
            'src_bytes': row['src_bytes'],
            'service':   row['service'],
            'src_ip':    packet[IP].src if packet.haslayer(IP) else 'unknown',
            'dst_ip':    packet[IP].dst if packet.haslayer(IP) else 'unknown',
            'protocol':  row['protocol_type'],
            'flag':      row['flag'],
            'alert':     pred == 1,
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
        err_event = {'ts': time.time(), 'error': str(exc)}
        if live_events.full():
            try:
                live_events.get_nowait()
            except queue.Empty:
                pass
        live_events.put(err_event)
        print(f"[Sniffer] Error processing packet: {exc}")


def get_active_interface():
    # Prefer an explicitly selected interface
    with _sniff_lock:
        if selected_interface:
            try:
                ip = get_if_addr(selected_interface)
            except Exception:
                ip = None
            print(f"[Sniffer] Using selected interface: {selected_interface} ({ip})")
            return selected_interface

    # Otherwise auto-detect a usable interface
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != '0.0.0.0':
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
                print(f"[Sniffer] Using interface: {iface} ({ip})")
                return iface
        except Exception:
            continue
<<<<<<< HEAD
    print("[Sniffer] No active interface found. Defaulting to 'lo'")
    return 'lo'  # fallback to loopback

def send_email_alert(subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECIPIENT

=======
    print("[Sniffer] No active interface found — defaulting to 'lo'")
    return 'lo'


def send_email_alert(subject, body):
    try:
        msg            = MIMEText(body)
        msg['Subject'] = subject
        msg['From']    = EMAIL_SENDER
        msg['To']      = EMAIL_RECIPIENT
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("[Alert] Email sent.")
<<<<<<< HEAD
    except Exception as e:
        print(f"[Alert] Failed to send email: {e}")



def run_sniffer():
    iface = get_active_interface()
    print("[Sniffer] Ready.")
    while True:
        if sniffing_enabled:
            try:
                sniff(prn=packet_handler, iface=iface, store=False, timeout=5)
            except Exception as e:
                print(f"[Sniffer] Error: {e}")
=======
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
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
        else:
            time.sleep(1)


<<<<<<< HEAD
# ---------------- Flask Routes ----------------
=======
# ------------------------------------------------------------------ #
#  Flask routes                                                        #
# ------------------------------------------------------------------ #

>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
@app.route('/')
def index():
    return render_template('index.html')

<<<<<<< HEAD
=======

>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
@app.route('/predict-file', methods=['POST'])
def predict_file():
    if 'file' not in request.files:
        return jsonify({'error': 'no file provided'}), 400
    df = pd.read_csv(request.files['file'], header=None)
    if df.shape[1] != len(FEATURE_COLUMNS):
<<<<<<< HEAD
        return jsonify({'error': 'CSV must have 41 features'}), 400
    df.columns = FEATURE_COLUMNS
    preds = model.predict(scaler.transform(df))
    return jsonify({'n_samples': len(preds),
                    'predictions_sample': preds.tolist()[:20]})

@app.route('/toggle-sniffing', methods=['POST'])
def toggle_sniffing():
    global sniffing_enabled
    sniffing_enabled = not sniffing_enabled
    return jsonify({'sniffing': sniffing_enabled})
=======
        return jsonify({'error': f'CSV must have {len(FEATURE_COLUMNS)} features'}), 400
    df.columns = FEATURE_COLUMNS

    # FIX 4: encode categoricals before scaling (missing in original)
    for col in ('protocol_type', 'service', 'flag'):
        df[col] = df[col].apply(lambda v: safe_transform(encoders[col], v))
    df = df.apply(pd.to_numeric, errors='coerce')

    preds = model.predict(scaler.transform(df))
    return jsonify({
        'n_samples':          len(preds),
        'predictions_sample': preds.tolist()[:20],
    })


@app.route('/toggle-sniffing', methods=['POST'])
def toggle_sniffing():
    # FIX 6: lock around shared state mutation
    global sniffing_enabled
    with _sniff_lock:
        sniffing_enabled = not sniffing_enabled
        state = sniffing_enabled
    return jsonify({'sniffing': state})


@app.route('/interfaces')
def list_interfaces():
    """Return available interfaces and their addresses."""
    res = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = None
        res.append({'iface': iface, 'addr': ip})
    # include currently selected interface
    with _sniff_lock:
        cur = selected_interface
    return jsonify({'interfaces': res, 'selected': cur})


@app.route('/set-interface', methods=['POST'])
def set_interface():
    data = request.get_json() or {}
    iface = data.get('iface')
    if not iface:
        return jsonify({'error': 'missing iface'}), 400
    # validate
    if iface not in get_if_list():
        return jsonify({'error': 'unknown iface'}), 400
    global selected_interface
    with _sniff_lock:
        selected_interface = iface
    return jsonify({'selected': selected_interface})

>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)

@app.route('/predict-single', methods=['POST'])
def predict_single():
    data = request.get_json()
    if not data or 'sample' not in data:
        return jsonify({'error': 'missing sample'}), 400
    parts = [p.strip() for p in data['sample'].split(',')]
    if len(parts) != len(FEATURE_COLUMNS):
<<<<<<< HEAD
        return jsonify({'error': f'expected {len(FEATURE_COLUMNS)} features'}), 400
    df = pd.DataFrame([parts], columns=FEATURE_COLUMNS)
    for col in ['protocol_type', 'service', 'flag']:
        df[col] = encoders[col].transform([df.at[0, col]])
    X = scaler.transform(df.apply(pd.to_numeric, errors='coerce'))

    pred = model.predict(X)[0]
    return jsonify({'prediction': str(pred)})

@app.route('/live-status')
def live_status():
    items = list(live_events.queue)
    summary = {
        'total': len(items),
        'normal': sum(1 for i in items if i.get('pred') == 0),
        'attack': sum(1 for i in items if i.get('pred') == 1)
    }
    return jsonify({'summary': summary, 'recent': items[-20:]})

# ---------------- Main ----------------
if __name__ == '__main__':
    t_sniff = threading.Thread(target=run_sniffer, daemon=True)
    Thread(target=run_sniffer, daemon=True).start()
=======
        return jsonify({'error': f'expected {len(FEATURE_COLUMNS)} features, got {len(parts)}'}), 400

    df = pd.DataFrame([parts], columns=FEATURE_COLUMNS)
    # FIX 5: safe_transform instead of bare encoder.transform
    for col in ('protocol_type', 'service', 'flag'):
        df[col] = safe_transform(encoders[col], df.at[0, col])

    X    = scaler.transform(df.apply(pd.to_numeric, errors='coerce'))
    pred = int(model.predict(X)[0])
    return jsonify({'prediction': pred, 'label': 'Attack' if pred == 1 else 'Normal'})


@app.route('/live-status')
def live_status():
    # FIX 7: snapshot the queue safely without touching internal .queue
    items = []
    tmp: "queue.Queue[dict]" = queue.Queue()
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
        'total':  len(items),
        'normal': sum(1 for i in items if i.get('pred') == 0),
        'attack': sum(1 for i in items if i.get('pred') == 1),
    }
    return jsonify({'summary': summary, 'recent': items[-20:]})


# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #
if __name__ == '__main__':
    # FIX 1: start the sniffer thread exactly once (original started it twice)
    t_sniff = threading.Thread(target=run_sniffer, daemon=True)
>>>>>>> 42e2167 (Add interface selection UI and server endpoints; refresh sniff interface each loop)
    t_sniff.start()
    app.run(debug=True)
