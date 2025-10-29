
---

# 🛡️ Real-Time Intrusion Detection System (Live IDS)

A modular, Flask-powered real-time Intrusion Detection System (IDS) that captures live network traffic, extracts behavioral features, and classifies packets using a trained machine learning model. Designed for security research, lab automation, and forensic analysis.

---

## 🚀 Features

- 🔍 **Live Packet Sniffing** using Scapy
- 🧠 **ML-Based Classification** (Normal vs. Attack) with pre-trained model
- 📊 **Real-Time Dashboard** with scrollable event log and visual alerts
- 🔔 **Email Notifications** on attack detection
- 🧠 **Stateful Feature Extraction** (e.g., rolling `count`, `serror_rate`)
- 📁 **CSV Upload Support** for offline prediction
- 🌐 **Auto-detects Active Network Interface**

---

## 🧠 How It Works

1. **Packet Capture**: Scapy sniffs packets on the active interface.
2. **Feature Extraction**: Each packet is converted into a 41-feature vector (NSL-KDD style), including protocol, service, flags, byte counts, and rolling metrics.
3. **Preprocessing**: Categorical fields are encoded, numeric fields scaled using saved encoders and scalers.
4. **Prediction**: A trained ML model (e.g., RandomForest) classifies the packet as normal (`0`) or attack (`1`).
5. **Dashboard Update**: The result is pushed to a live dashboard with color-coded rows and optional alert banners.
6. **Email Alert**: If an attack is detected, an email is sent with timestamp, service, and source IP.

---

## 🛠️ Installation & Setup

```bash
# Clone the repo
git clone https://github.com/yourusername/live-ids.git
cd live-ids

# Create virtual environment
python3 -m venv ids_env
source ids_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python live_ids.py
```

> Make sure you have `scapy`, `flask`, `joblib`, `pandas`, and `sklearn` installed.

---

## 📦 Required Files

- `ids_model.joblib` – Trained ML model (e.g., RandomForest)
- `scaler.joblib` – Scaler used during training
- `protocol_type_encoder.joblib`, `service_encoder.joblib`, `flag_encoder.joblib` – Label encoders

---

## 📬 Email Alert Setup

Edit these variables in `live_ids.py`:

```python
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECIPIENT = "your_email@gmail.com"
```

Use an **App Password** if using Gmail with 2FA.

---

## 🧪 Testing

- Use `curl` or Scapy to simulate traffic:
  ```python
  from scapy.all import IP, TCP, send
  for _ in range(20):
      send(IP(dst="127.0.0.1")/TCP(dport=80, flags="S"))
  ```

- Upload a CSV file via the dashboard to test batch predictions.

---

## 🐞 Known Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| `y contains previously unseen labels: np.int64(6)` | Protocol number (e.g., 6 for TCP) passed to encoder expecting string | Map proto to `'tcp'`, `'udp'`, etc. |
| `ValueError: Found unknown categories` | Encoder sees unseen label | Use `safe_transform()` or retrain with `OrdinalEncoder(handle_unknown='use_encoded_value')` |
| No attacks detected | Features too benign (e.g., single packet) | Simulate burst traffic to trigger rolling metrics |
| Dashboard not updating | JavaScript polling not active | Ensure `pollStatus()` is called with `setInterval()` |

---

## 📈 Roadmap Ideas

- [ ] Modal popups for full packet details
- [ ] CSV export of event log
- [ ] Webhook alerts (Discord, Slack)
- [ ] Attack type inference (e.g., SYN flood, port scan)
- [ ] PCAP replay support

---

## 👨‍💻 Author

Built by TONGA NOUDJA MARC-DONALD — cybersecurity Analyst, system Security architect, and automation enthusiast.  
Modular, extensible, and designed for clarity, reproducibility, and real-time insight.

---
