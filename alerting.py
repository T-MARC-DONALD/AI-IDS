import base64
import json
import os
import smtplib
import threading
import time
from email.mime.text import MIMEText
from urllib import error, parse, request


class AlertManager:
    SERVER_MANAGED_FIELDS = {
        "email": {
            "EMAIL_SENDER",
            "SMTP_USERNAME",
            "EMAIL_PASSWORD",
            "SMTP_SERVER",
            "SMTP_PORT",
        },
        "telegram": {
            "TELEGRAM_BOT_TOKEN",
        },
    }

    SERVER_MANAGED_COPY = {
        "email": "SMTP sender, login, password, and host are preconfigured on this machine. Only the receiving email is editable here.",
        "telegram": "The Telegram bot token is preconfigured on this machine. Only the destination chat ID is editable here.",
    }

    CHANNEL_SPECS = {
        "email": {
            "label": "Email",
            "transport": "SMTP",
            "hint": "Provide sender, SMTP login, password, recipient, and SMTP host details.",
            "destination_env": "EMAIL_RECIPIENT",
            "fields": [
                {"env": "EMAIL_SENDER", "label": "Sender email", "required": True, "input_type": "email"},
                {"env": "SMTP_USERNAME", "label": "SMTP username", "required": False, "input_type": "text"},
                {"env": "EMAIL_PASSWORD", "label": "App password", "required": True, "secret": True, "input_type": "password"},
                {"env": "EMAIL_RECIPIENT", "label": "Recipient email", "required": True, "input_type": "email"},
                {"env": "SMTP_SERVER", "label": "SMTP server", "required": False, "input_type": "text", "default": "smtp.gmail.com"},
                {"env": "SMTP_PORT", "label": "SMTP port", "required": False, "input_type": "number", "default": "587"},
            ],
        },
        "telegram": {
            "label": "Telegram",
            "transport": "Bot API",
            "hint": "Provide the recipient chat ID.",
            "destination_env": "TELEGRAM_CHAT_ID",
            "fields": [
                {"env": "TELEGRAM_BOT_TOKEN", "label": "Bot token", "required": True, "secret": True, "input_type": "password"},
                {"env": "TELEGRAM_CHAT_ID", "label": "Recipient chat ID", "required": True, "input_type": "text"},
            ],
        },
        "whatsapp_twilio": {
            "label": "WhatsApp",
            "transport": "Twilio API",
            "hint": "Provide Twilio account credentials and WhatsApp sender/recipient numbers.",
            "destination_env": "TWILIO_WHATSAPP_TO",
            "fields": [
                {"env": "TWILIO_ACCOUNT_SID", "label": "Account SID", "required": True, "input_type": "text"},
                {"env": "TWILIO_AUTH_TOKEN", "label": "Auth token", "required": True, "secret": True, "input_type": "password"},
                {"env": "TWILIO_WHATSAPP_FROM", "label": "From number", "required": True, "input_type": "text"},
                {"env": "TWILIO_WHATSAPP_TO", "label": "Recipient number", "required": True, "input_type": "text"},
            ],
        },
        "whatsapp_cloud": {
            "label": "WhatsApp",
            "transport": "Meta Cloud API",
            "hint": "Provide a Cloud API token, phone number ID, and recipient number.",
            "destination_env": "WHATSAPP_CLOUD_TO",
            "fields": [
                {"env": "WHATSAPP_CLOUD_TOKEN", "label": "Access token", "required": True, "secret": True, "input_type": "password"},
                {"env": "WHATSAPP_CLOUD_PHONE_NUMBER_ID", "label": "Phone number ID", "required": True, "input_type": "text"},
                {"env": "WHATSAPP_CLOUD_TO", "label": "Recipient number", "required": True, "input_type": "text"},
            ],
        },
    }

    def __init__(self, environ=None):
        self.environ = environ or os.environ
        self.config_path = self.environ.get("ALERT_CONFIG_PATH", "./alert_channels.local.json")
        self._lock = threading.Lock()
        self._channel_state = {}
        self._last_dispatch_ts = None
        self._last_dispatch_subject = None
        self._persisted = self._load_persisted_config()
        self._channels = self._build_channels()

    def _load_persisted_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return {"channels": {}}
        except json.JSONDecodeError:
            print(f"[Alert] Ignoring invalid alert config file: {self.config_path}")
            return {"channels": {}}

        if not isinstance(data, dict):
            return {"channels": {}}

        channels = data.get("channels")
        if not isinstance(channels, dict):
            channels = {}
        return {"channels": channels}

    def _save_persisted_config(self):
        folder = os.path.dirname(os.path.abspath(self.config_path))
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(self._persisted, handle, indent=2)

    def _field_value(self, channel_key, env_key, default=""):
        if self._is_env_managed_field(channel_key, env_key):
            return self.environ.get(env_key, default)

        channel_config = self._persisted.get("channels", {}).get(channel_key, {})
        settings = channel_config.get("settings", {})
        if env_key in settings:
            return settings.get(env_key, "")
        return self.environ.get(env_key, default)

    def _is_env_managed_field(self, channel_key, env_key):
        managed_fields = self.SERVER_MANAGED_FIELDS.get(channel_key, set())
        return env_key in managed_fields and bool(str(self.environ.get(env_key, "")).strip())

    def _channel_enabled(self, channel_key, configured):
        channel_config = self._persisted.get("channels", {}).get(channel_key, {})
        if "enabled" in channel_config:
            return bool(channel_config.get("enabled"))
        return configured

    def _build_channels(self):
        senders = {
            "email": self._send_email,
            "telegram": self._send_telegram,
            "whatsapp_twilio": self._send_twilio_whatsapp,
            "whatsapp_cloud": self._send_whatsapp_cloud,
        }

        channels = {}
        for channel_key, spec in self.CHANNEL_SPECS.items():
            fields = []
            resolved_settings = {}
            for field in spec["fields"]:
                value = self._field_value(channel_key, field["env"], field.get("default", ""))
                resolved_settings[field["env"]] = value
                fields.append({
                    "env": field["env"],
                    "label": field["label"],
                    "required": bool(field.get("required")),
                    "secret": bool(field.get("secret")),
                    "input_type": field.get("input_type", "text"),
                    "editable": not self._is_env_managed_field(channel_key, field["env"]),
                    "value": "" if field.get("secret") else value,
                    "configured": bool(str(value).strip()) if field.get("secret") else None,
                })

            configured = all(
                str(resolved_settings[field["env"]]).strip()
                for field in spec["fields"]
                if field.get("required")
            )

            channels[channel_key] = {
                "key": channel_key,
                "label": spec["label"],
                "transport": spec["transport"],
                "configured": configured,
                "enabled": self._channel_enabled(channel_key, configured),
                "destination": resolved_settings.get(spec["destination_env"], ""),
                "hint": spec["hint"],
                "server_managed": any(
                    self._is_env_managed_field(channel_key, field["env"])
                    for field in spec["fields"]
                ),
                "server_managed_copy": self.SERVER_MANAGED_COPY.get(channel_key),
                "fields": fields,
                "settings": resolved_settings,
                "sender": senders[channel_key],
            }
        return channels

    @property
    def has_external_channels(self):
        return any(channel["configured"] and channel["enabled"] for channel in self._channels.values())

    def enabled_labels(self):
        return [
            f"{channel['label']} ({channel['transport']})"
            for channel in self._channels.values()
            if channel["configured"] and channel["enabled"]
        ]

    def configure_channel(self, channel_key, enabled=None, settings=None):
        if channel_key not in self.CHANNEL_SPECS:
            raise KeyError(channel_key)

        channel_config = self._persisted.setdefault("channels", {}).setdefault(channel_key, {})
        channel_settings = channel_config.setdefault("settings", {})
        spec = self.CHANNEL_SPECS[channel_key]

        if enabled is not None:
            channel_config["enabled"] = bool(enabled)

        settings = settings or {}
        for field in spec["fields"]:
            env_key = field["env"]
            if self._is_env_managed_field(channel_key, env_key):
                continue
            if env_key not in settings:
                continue

            raw_value = settings.get(env_key)
            if raw_value is None:
                continue

            value = str(raw_value).strip()
            if field.get("secret"):
                if value:
                    channel_settings[env_key] = value
            else:
                channel_settings[env_key] = value

        self._save_persisted_config()
        self._channels = self._build_channels()
        return self.snapshot()

    def _record_result(self, channel, ok, message, attempt_ts):
        with self._lock:
            state = self._channel_state.setdefault(channel["key"], {})
            state["last_attempt_ts"] = attempt_ts
            state["last_result"] = "delivered" if ok else "failed"
            state["last_message"] = message
            if ok:
                state["last_sent_ts"] = attempt_ts

    def snapshot(self):
        with self._lock:
            channel_state = dict(self._channel_state)
            last_dispatch_ts = self._last_dispatch_ts
            last_dispatch_subject = self._last_dispatch_subject

        channels = []
        configured_count = 0
        enabled_count = 0
        healthy_count = 0
        for channel in self._channels.values():
            if channel["configured"]:
                configured_count += 1
            if channel["configured"] and channel["enabled"]:
                enabled_count += 1
            state = channel_state.get(channel["key"], {})
            last_result = state.get("last_result")
            channels.append({
                "key": channel["key"],
                "label": channel["label"],
                "transport": channel["transport"],
                "configured": channel["configured"],
                "enabled": channel["enabled"],
                "destination": channel["destination"],
                "hint": channel["hint"],
                "server_managed": channel.get("server_managed", False),
                "server_managed_copy": channel.get("server_managed_copy"),
                "fields": channel["fields"],
                "last_result": last_result,
                "last_message": state.get("last_message"),
                "last_attempt_ts": state.get("last_attempt_ts"),
                "last_sent_ts": state.get("last_sent_ts"),
            })
            if channel["configured"] and channel["enabled"] and last_result != "failed":
                healthy_count += 1

        return {
            "channels": channels,
            "summary": {
                "configured_count": configured_count,
                "enabled_count": enabled_count,
                "healthy_count": healthy_count,
                "last_dispatch_ts": last_dispatch_ts,
                "last_dispatch_subject": last_dispatch_subject,
                "mode": "multi-channel" if enabled_count else "log-only",
            },
        }

    def send_attack_alert_async(self, event):
        threading.Thread(target=self.send_attack_alert, args=(event,), daemon=True).start()

    def send_attack_alert(self, event, channel_keys=None):
        subject = f"IDS Alert: {event.get('attack_type') or 'Attack'} Detected"
        body = self._format_attack_body(event)
        return self._dispatch(subject, body, channel_keys=channel_keys)

    def send_test_alert(self, channel_keys=None):
        subject = "IDS Test Alert"
        body = (
            "This is a manual test notification from AI-IDS Watchfloor.\n\n"
            f"Generated: {time.ctime()}\n"
            "If you received this, the alert channel is working."
        )
        return self._dispatch(subject, body, channel_keys=channel_keys)

    def _dispatch(self, subject, body, channel_keys=None):
        channels = self._resolve_channels(channel_keys)
        results = []

        if not channels:
            print(f"[Alert] No configured external channels. Logged only: {subject}")
            return results

        with self._lock:
            self._last_dispatch_ts = time.time()
            self._last_dispatch_subject = subject

        for channel in channels:
            attempt_ts = time.time()
            if not channel["configured"]:
                message = "Channel not configured."
                self._record_result(channel, False, message, attempt_ts)
                results.append({
                    "channel": channel["key"],
                    "label": channel["label"],
                    "transport": channel["transport"],
                    "ok": False,
                    "message": message,
                })
                continue

            try:
                channel["sender"](subject, body)
                message = self._success_message(channel)
                self._record_result(channel, True, message, attempt_ts)
                print(f"[Alert] {channel['label']} sent via {channel['transport']}.")
                results.append({
                    "channel": channel["key"],
                    "label": channel["label"],
                    "transport": channel["transport"],
                    "ok": True,
                    "message": message,
                })
            except Exception as exc:
                message = str(exc)
                self._record_result(channel, False, message, attempt_ts)
                print(f"[Alert] {channel['label']} failed via {channel['transport']}: {message}")
                results.append({
                    "channel": channel["key"],
                    "label": channel["label"],
                    "transport": channel["transport"],
                    "ok": False,
                    "message": message,
                })

        return results

    def _success_message(self, channel):
        if channel["key"] == "email":
            return "Accepted by SMTP server. Inbox delivery is not confirmed by the app."
        return f"Delivered via {channel['transport']}."

    def _resolve_channels(self, channel_keys=None):
        if channel_keys:
            keys = []
            for channel_key in channel_keys:
                if channel_key == "all":
                    return [channel for channel in self._channels.values() if channel["configured"]]
                if channel_key in self._channels:
                    keys.append(channel_key)
            return [self._channels[key] for key in keys if self._channels[key]["configured"]]
        return [channel for channel in self._channels.values() if channel["configured"] and channel["enabled"]]

    def _format_attack_body(self, event):
        return (
            f"Time:        {time.ctime(event.get('ts') or time.time())}\n"
            f"Source:      {event.get('src_ip', 'unknown')}:{event.get('src_port', '-') }\n"
            f"Destination: {event.get('dst_ip', 'unknown')}:{event.get('dst_port', '-')}\n"
            f"Protocol:    {event.get('protocol', 'unknown')}\n"
            f"Attack type: {event.get('attack_type') or 'unknown'}\n"
            f"Fwd/Bwd packets: {event.get('total_fwd_packets', '-')} / {event.get('total_bwd_packets', '-')}\n"
            f"Flow duration (us): {event.get('flow_duration_us', '-')}\n"
            f"Flow bytes/s: {event.get('flow_bytes_per_s', '-')}"
        )

    def _send_email(self, subject, body):
        settings = self._channels["email"]["settings"]
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.get("EMAIL_SENDER", "")
        msg["To"] = settings.get("EMAIL_RECIPIENT", "")

        smtp_server = settings.get("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(settings.get("SMTP_PORT", "587"))
        smtp_username = settings.get("SMTP_USERNAME", "").strip() or settings.get("EMAIL_SENDER", "")

        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(
                smtp_username,
                settings.get("EMAIL_PASSWORD", ""),
            )
            server.send_message(msg)

    def _send_telegram(self, subject, body):
        settings = self._channels["telegram"]["settings"]
        token = settings.get("TELEGRAM_BOT_TOKEN", "")
        payload = {
            "chat_id": settings.get("TELEGRAM_CHAT_ID", ""),
            "text": f"{subject}\n\n{body}",
            "disable_web_page_preview": True,
        }
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        self._post_json(url, payload)

    def discover_telegram_chat(self):
        settings = self._channels["telegram"]["settings"]
        token = settings.get("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("Telegram bot token is not configured on this machine.")

        payload = self._fetch_json(f"https://api.telegram.org/bot{token}/getUpdates")
        updates = payload.get("result") or []
        for update in reversed(updates):
            chat = self._extract_telegram_chat(update)
            if not chat:
                continue

            label_parts = [chat.get("type") or "chat"]
            if chat.get("title"):
                label_parts.append(chat["title"])
            elif chat.get("username"):
                label_parts.append(f"@{chat['username']}")
            elif chat.get("first_name") or chat.get("last_name"):
                label_parts.append(" ".join(part for part in [chat.get("first_name"), chat.get("last_name")] if part))

            return {
                "chat_id": str(chat.get("id", "")),
                "chat_type": chat.get("type") or "unknown",
                "chat_label": " · ".join(part for part in label_parts if part),
            }

        raise RuntimeError("No Telegram chat was found yet. Open the bot, press Start, then try again.")

    def _send_twilio_whatsapp(self, subject, body):
        settings = self._channels["whatsapp_twilio"]["settings"]
        account_sid = settings.get("TWILIO_ACCOUNT_SID", "")
        auth_token = settings.get("TWILIO_AUTH_TOKEN", "")
        auth_bytes = f"{account_sid}:{auth_token}".encode("utf-8")
        auth_header = base64.b64encode(auth_bytes).decode("ascii")
        message_body = f"{subject}\n\n{body}"
        payload = parse.urlencode({
            "From": self._as_whatsapp_address(settings.get("TWILIO_WHATSAPP_FROM", "")),
            "To": self._as_whatsapp_address(settings.get("TWILIO_WHATSAPP_TO", "")),
            "Body": message_body,
        }).encode("utf-8")
        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
        req = request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        self._open_request(req)

    def _send_whatsapp_cloud(self, subject, body):
        settings = self._channels["whatsapp_cloud"]["settings"]
        phone_number_id = settings.get("WHATSAPP_CLOUD_PHONE_NUMBER_ID", "")
        access_token = settings.get("WHATSAPP_CLOUD_TOKEN", "")
        url = f"https://graph.facebook.com/v22.0/{phone_number_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": settings.get("WHATSAPP_CLOUD_TO", ""),
            "type": "text",
            "text": {
                "preview_url": False,
                "body": f"{subject}\n\n{body}",
            },
        }
        self._post_json(url, payload, headers={"Authorization": f"Bearer {access_token}"})

    def _post_json(self, url, payload, headers=None):
        req = request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        self._open_request(req)

    def _fetch_json(self, url, headers=None):
        req = request.Request(
            url,
            headers=headers or {},
            method="GET",
        )
        try:
            with request.urlopen(req, timeout=15) as response:
                payload = response.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(payload or exc.reason) from exc
        except error.URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

        try:
            data = json.loads(payload or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("Telegram returned an invalid response.") from exc

        if data.get("ok") is False:
            raise RuntimeError(data.get("description") or "Telegram request failed.")
        return data

    def _extract_telegram_chat(self, update):
        for key in ("message", "edited_message", "channel_post", "edited_channel_post"):
            chat = (update.get(key) or {}).get("chat")
            if chat:
                return chat

        callback_message = ((update.get("callback_query") or {}).get("message") or {})
        return callback_message.get("chat")

    def _open_request(self, req):
        try:
            with request.urlopen(req, timeout=15) as response:
                response.read()
        except error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(payload or exc.reason) from exc
        except error.URLError as exc:
            raise RuntimeError(str(exc.reason)) from exc

    def _as_whatsapp_address(self, value):
        if value.startswith("whatsapp:"):
            return value
        return f"whatsapp:{value}"