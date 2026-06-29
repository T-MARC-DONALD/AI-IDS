"""
flow_record.py

Stage 1: FlowRecord class.

Accumulates packets belonging to one flow (5-tuple: src_ip, src_port,
dst_ip, dst_port, protocol) and computes a subset of the 78
CICFlowMeter-style features used by the trained models.

STAGE 1 COVERS (~55 of 78 features):
  - Basic counts: Total Fwd/Bwd Packets, Total Length of Fwd/Bwd Packets
  - Packet length stats: Fwd/Bwd Packet Length Max/Min/Mean/Std,
    Min/Max/Mean/Std/Variance Packet Length, Average Packet Size,
    Avg Fwd/Bwd Segment Size
  - Flow rate: Flow Bytes/s, Flow Packets/s, Fwd Packets/s, Bwd Packets/s
  - Timing: Flow Duration, Flow/Fwd/Bwd IAT Mean/Std/Max/Min/Total
  - TCP flags: FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count,
    Fwd/Bwd PSH/URG Flags
  - Header lengths: Fwd/Bwd Header Length (+ duplicate column)
  - Down/Up Ratio
  - Destination Port

NOT YET COVERED (Stage 2 - placeholder zeros for now):
  - Active/Idle Mean/Std/Max/Min
  - Fwd/Bwd Avg Bytes/Packets/Bulk Rate (Bulk transfer features)
  - Subflow Fwd/Bwd Packets/Bytes
  - Init_Win_bytes_forward/backward
  - act_data_pkt_fwd, min_seg_size_forward

Usage (standalone test at bottom):
    python flow_record.py
"""

import numpy as np
from scapy.all import IP, TCP, UDP


# TCP flag bit positions (standard)
TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,  # CWE in CICFlowMeter naming
}


def safe_mean(values):
    return float(np.mean(values)) if values else 0.0


def safe_std(values):
    return float(np.std(values)) if len(values) > 1 else 0.0


def safe_max(values):
    return float(np.max(values)) if values else 0.0


def safe_min(values):
    return float(np.min(values)) if values else 0.0


def iat_stats(timestamps):
    """Given a sorted list of timestamps, return (total, mean, std, max, min)
    of inter-arrival times. Returns zeros if fewer than 2 timestamps."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    diffs = np.diff(sorted(timestamps))
    return (
        float(np.sum(diffs)),
        float(np.mean(diffs)),
        float(np.std(diffs)) if len(diffs) > 1 else 0.0,
        float(np.max(diffs)),
        float(np.min(diffs)),
    )


class FlowRecord:
    """
    Accumulates statistics for one network flow (5-tuple).

    A flow is "forward" direction = packets from the original source
    (the side that sent the first packet) to the destination.
    "Backward" = the reply direction.
    """

    # Flow considered expired if no packet seen for this many seconds
    ACTIVITY_TIMEOUT = 120.0

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol, first_pkt_time):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol  # 6=TCP, 17=UDP

        self.start_time = first_pkt_time
        self.last_seen = first_pkt_time

        # Per-direction packet length lists
        self.fwd_lengths = []
        self.bwd_lengths = []

        # Per-direction timestamps (for IAT calculations)
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        self.all_timestamps = []

        # Per-direction header length totals
        self.fwd_header_total = 0
        self.bwd_header_total = 0

        # TCP flag counts (aggregated across both directions, as CICFlowMeter does)
        self.flag_counts = {k: 0 for k in TCP_FLAGS}

        # Per-direction PSH/URG flag presence (CICFlowMeter: count of packets
        # with that flag set, in that direction)
        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0

        # --- Stage 2 state ---

        # TCP initial window size (from the FIRST packet seen in each direction)
        self.init_win_bytes_fwd = None
        self.init_win_bytes_bwd = None

        # Minimum header length seen on forward packets (CICFlowMeter's
        # "min_seg_size_forward" - despite the name, it's the min header size,
        # not segment/payload size)
        self.min_seg_size_fwd = None

        # Count of forward packets that carry a payload (TCP/UDP data length > 0)
        self.act_data_pkt_fwd = 0

        # --- Active/Idle period tracking ---
        # CICFlowMeter defines an "idle" gap as > IDLE_THRESHOLD seconds with
        # no packets. Time accumulated between idle gaps is one "active" period.
        self.IDLE_THRESHOLD = 1.0  # seconds

        self.active_durations = []  # completed active-period durations
        self.idle_durations = []    # completed idle-gap durations

        # Tracks the current active period: (start_time, last_pkt_time)
        self._active_start = None
        self._active_last = None

        # --- Bulk transfer tracking ---
        # CICFlowMeter "bulk": >= BULK_MIN_PACKETS consecutive packets in the
        # SAME direction, each carrying payload, with inter-arrival time
        # < BULK_IAT_THRESHOLD (no reverse-direction packet interrupting).
        self.BULK_MIN_PACKETS = 4

        # Per-direction running bulk state: current run of consecutive
        # same-direction payload packets
        self._fwd_bulk_run_packets = 0
        self._fwd_bulk_run_bytes = 0
        self._fwd_bulk_run_start = None
        self._fwd_bulk_run_last = None

        self._bwd_bulk_run_packets = 0
        self._bwd_bulk_run_bytes = 0
        self._bwd_bulk_run_start = None
        self._bwd_bulk_run_last = None

        # Completed bulks: list of (packet_count, byte_count, duration)
        self.fwd_bulks = []
        self.bwd_bulks = []

        # Last direction seen (to detect direction changes for bulk tracking)
        self._last_direction = None

    def is_expired(self, now):
        return (now - self.last_seen) > self.ACTIVITY_TIMEOUT

    def add_packet(self, pkt, pkt_time, direction):
        """
        direction: 'fwd' or 'bwd' relative to the flow's original sender.
        """
        self._update_active_idle(pkt_time)

        self.last_seen = pkt_time
        self.all_timestamps.append(pkt_time)

        pkt_len = len(pkt)

        if IP in pkt:
            ihl = pkt[IP].ihl
            ip_header_len = ihl * 4 if ihl is not None else 20
            total_len = pkt[IP].len if pkt[IP].len is not None else pkt_len
        else:
            ip_header_len = 0
            total_len = pkt_len

        transport_header_len = 0
        flags = None
        win = None
        payload_len = 0

        if TCP in pkt:
            dataofs = pkt[TCP].dataofs
            transport_header_len = dataofs * 4 if dataofs is not None else 20
            flags = pkt[TCP].flags
            win = pkt[TCP].window
            payload_len = max(total_len - ip_header_len - transport_header_len, 0)
        elif UDP in pkt:
            transport_header_len = 8  # UDP header is fixed 8 bytes
            udp_len = pkt[UDP].len if pkt[UDP].len is not None else 0
            payload_len = max(udp_len - transport_header_len, 0)

        header_len = ip_header_len + transport_header_len

        if direction == "fwd":
            self.fwd_lengths.append(pkt_len)
            self.fwd_timestamps.append(pkt_time)
            self.fwd_header_total += header_len

            # Initial window size: first forward packet only
            if self.init_win_bytes_fwd is None and win is not None:
                self.init_win_bytes_fwd = win

            # min header size seen on forward packets
            if self.min_seg_size_fwd is None or header_len < self.min_seg_size_fwd:
                self.min_seg_size_fwd = header_len

            # forward packets carrying payload
            if payload_len > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.bwd_lengths.append(pkt_len)
            self.bwd_timestamps.append(pkt_time)
            self.bwd_header_total += header_len

            # Initial window size: first backward packet only
            if self.init_win_bytes_bwd is None and win is not None:
                self.init_win_bytes_bwd = win

        # TCP flags (aggregate counts + per-direction PSH/URG)
        if flags is not None:
            flags_int = int(flags)
            for name, bit in TCP_FLAGS.items():
                if flags_int & bit:
                    self.flag_counts[name] += 1

            if flags_int & TCP_FLAGS["PSH"]:
                if direction == "fwd":
                    self.fwd_psh += 1
                else:
                    self.bwd_psh += 1

            if flags_int & TCP_FLAGS["URG"]:
                if direction == "fwd":
                    self.fwd_urg += 1
                else:
                    self.bwd_urg += 1

        self._update_bulk(direction, pkt_time, payload_len)
        self._last_direction = direction

    # ------------------------------------------------------------------
    # Active / Idle period tracking
    # ------------------------------------------------------------------

    def _update_active_idle(self, pkt_time):
        """
        Called BEFORE updating last_seen/timestamps for the new packet.
        If the gap since the last packet exceeds IDLE_THRESHOLD, close the
        current active period (record its duration) and record the idle gap.
        Otherwise, extend the current active period.
        """
        if self._active_start is None:
            # First packet of the flow - starts the first active period
            self._active_start = pkt_time
            self._active_last = pkt_time
            return

        gap = pkt_time - self._active_last

        if gap > self.IDLE_THRESHOLD:
            # Close current active period
            active_duration = self._active_last - self._active_start
            self.active_durations.append(active_duration)

            # Record the idle gap
            self.idle_durations.append(gap)

            # Start a new active period
            self._active_start = pkt_time
            self._active_last = pkt_time
        else:
            # Extend current active period
            self._active_last = pkt_time

    def _finalize_active_idle(self):
        """Call at flow expiry to close out the final active period."""
        if self._active_start is not None:
            active_duration = self._active_last - self._active_start
            self.active_durations.append(active_duration)

    # ------------------------------------------------------------------
    # Bulk transfer tracking
    # ------------------------------------------------------------------

    def _update_bulk(self, direction, pkt_time, payload_len):
        """
        Tracks runs of consecutive same-direction packets carrying payload.
        A run becomes a "bulk" once it reaches BULK_MIN_PACKETS. A run is
        closed (and checked against BULK_MIN_PACKETS) when:
          - a packet with no payload arrives in that direction, OR
          - a packet in the OPPOSITE direction arrives, OR
          - the gap since the last packet in this run exceeds IDLE_THRESHOLD
            (same threshold used for active/idle periods)
        """
        if direction == "fwd":
            # Close fwd run if the gap since its last packet is too large
            if (self._fwd_bulk_run_packets > 0 and self._fwd_bulk_run_last is not None
                    and (pkt_time - self._fwd_bulk_run_last) > self.IDLE_THRESHOLD):
                self._close_bulk_run("fwd")

            if payload_len > 0:
                if self._fwd_bulk_run_packets == 0:
                    self._fwd_bulk_run_start = pkt_time
                self._fwd_bulk_run_packets += 1
                self._fwd_bulk_run_bytes += payload_len
                self._fwd_bulk_run_last = pkt_time
            else:
                self._close_bulk_run("fwd")

            # A backward packet interrupts any in-progress backward run
            self._close_bulk_run("bwd")
        else:
            # Close bwd run if the gap since its last packet is too large
            if (self._bwd_bulk_run_packets > 0 and self._bwd_bulk_run_last is not None
                    and (pkt_time - self._bwd_bulk_run_last) > self.IDLE_THRESHOLD):
                self._close_bulk_run("bwd")

            if payload_len > 0:
                if self._bwd_bulk_run_packets == 0:
                    self._bwd_bulk_run_start = pkt_time
                self._bwd_bulk_run_packets += 1
                self._bwd_bulk_run_bytes += payload_len
                self._bwd_bulk_run_last = pkt_time
            else:
                self._close_bulk_run("bwd")

            # A forward packet interrupts any in-progress forward run
            self._close_bulk_run("fwd")

    def _close_bulk_run(self, direction):
        """If the current run for `direction` meets BULK_MIN_PACKETS,
        record it as a completed bulk. Reset the run regardless."""
        if direction == "fwd":
            if self._fwd_bulk_run_packets >= self.BULK_MIN_PACKETS:
                duration = self._fwd_bulk_run_last - self._fwd_bulk_run_start
                self.fwd_bulks.append(
                    (self._fwd_bulk_run_packets, self._fwd_bulk_run_bytes, duration)
                )
            self._fwd_bulk_run_packets = 0
            self._fwd_bulk_run_bytes = 0
            self._fwd_bulk_run_start = None
            self._fwd_bulk_run_last = None
        else:
            if self._bwd_bulk_run_packets >= self.BULK_MIN_PACKETS:
                duration = self._bwd_bulk_run_last - self._bwd_bulk_run_start
                self.bwd_bulks.append(
                    (self._bwd_bulk_run_packets, self._bwd_bulk_run_bytes, duration)
                )
            self._bwd_bulk_run_packets = 0
            self._bwd_bulk_run_bytes = 0
            self._bwd_bulk_run_start = None
            self._bwd_bulk_run_last = None

    def _finalize_bulk(self):
        """Call at flow expiry to flush any in-progress bulk runs."""
        self._close_bulk_run("fwd")
        self._close_bulk_run("bwd")

    # ------------------------------------------------------------------
    # Feature computation
    # ------------------------------------------------------------------

    def compute_features(self):
        """
        Returns a dict of feature_name -> value, covering all 78 features.
        Call this at flow expiry - it finalizes the in-progress active/idle
        period and any in-progress bulk runs before computing stats.
        """
        # Finalize open active/idle and bulk tracking
        self._finalize_active_idle()
        self._finalize_bulk()

        duration = max(self.last_seen - self.start_time, 0.0)
        # CICFlowMeter expresses Flow Duration in microseconds
        duration_us = duration * 1_000_000

        total_fwd_packets = len(self.fwd_lengths)
        total_bwd_packets = len(self.bwd_lengths)
        total_fwd_bytes = sum(self.fwd_lengths)
        total_bwd_bytes = sum(self.bwd_lengths)

        all_lengths = self.fwd_lengths + self.bwd_lengths

        # Flow rates (avoid div-by-zero -> 0, matches dropping inf rows upstream
        # but we still need a defined value here)
        if duration > 0:
            flow_bytes_per_s = (total_fwd_bytes + total_bwd_bytes) / duration
            flow_packets_per_s = (total_fwd_packets + total_bwd_packets) / duration
            fwd_packets_per_s = total_fwd_packets / duration
            bwd_packets_per_s = total_bwd_packets / duration
        else:
            flow_bytes_per_s = 0.0
            flow_packets_per_s = 0.0
            fwd_packets_per_s = 0.0
            bwd_packets_per_s = 0.0

        # iat_stats() returns values in seconds (Scapy epoch timestamps).
        # CICFlowMeter (and hence the training data) expresses ALL IAT
        # features in microseconds, just like Flow Duration.  Multiply by
        # 1e6 to match the scale the model was trained on.
        _ft, _fm, _fs, _fx, _fn = iat_stats(self.all_timestamps)
        flow_iat_total = _ft * 1_000_000
        flow_iat_mean  = _fm * 1_000_000
        flow_iat_std   = _fs * 1_000_000
        flow_iat_max   = _fx * 1_000_000
        flow_iat_min   = _fn * 1_000_000

        _ft, _fm, _fs, _fx, _fn = iat_stats(self.fwd_timestamps)
        fwd_iat_total = _ft * 1_000_000
        fwd_iat_mean  = _fm * 1_000_000
        fwd_iat_std   = _fs * 1_000_000
        fwd_iat_max   = _fx * 1_000_000
        fwd_iat_min   = _fn * 1_000_000

        _ft, _fm, _fs, _fx, _fn = iat_stats(self.bwd_timestamps)
        bwd_iat_total = _ft * 1_000_000
        bwd_iat_mean  = _fm * 1_000_000
        bwd_iat_std   = _fs * 1_000_000
        bwd_iat_max   = _fx * 1_000_000
        bwd_iat_min   = _fn * 1_000_000

        # Down/Up ratio: bwd packets / fwd packets (0 if fwd is 0)
        down_up_ratio = (total_bwd_packets / total_fwd_packets) if total_fwd_packets > 0 else 0.0

        avg_packet_size = safe_mean(all_lengths)
        avg_fwd_segment_size = safe_mean(self.fwd_lengths)
        avg_bwd_segment_size = safe_mean(self.bwd_lengths)

        packet_length_variance = float(np.var(all_lengths)) if all_lengths else 0.0

        features = {
            "Destination Port": self.dst_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": total_fwd_packets,
            "Total Backward Packets": total_bwd_packets,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,

            "Fwd Packet Length Max": safe_max(self.fwd_lengths),
            "Fwd Packet Length Min": safe_min(self.fwd_lengths),
            "Fwd Packet Length Mean": safe_mean(self.fwd_lengths),
            "Fwd Packet Length Std": safe_std(self.fwd_lengths),

            "Bwd Packet Length Max": safe_max(self.bwd_lengths),
            "Bwd Packet Length Min": safe_min(self.bwd_lengths),
            "Bwd Packet Length Mean": safe_mean(self.bwd_lengths),
            "Bwd Packet Length Std": safe_std(self.bwd_lengths),

            "Flow Bytes/s": flow_bytes_per_s,
            "Flow Packets/s": flow_packets_per_s,

            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,

            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,

            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,

            "Fwd PSH Flags": self.fwd_psh,
            "Bwd PSH Flags": self.bwd_psh,
            "Fwd URG Flags": self.fwd_urg,
            "Bwd URG Flags": self.bwd_urg,

            "Fwd Header Length": self.fwd_header_total,
            "Bwd Header Length": self.bwd_header_total,

            "Fwd Packets/s": fwd_packets_per_s,
            "Bwd Packets/s": bwd_packets_per_s,

            "Min Packet Length": safe_min(all_lengths),
            "Max Packet Length": safe_max(all_lengths),
            "Packet Length Mean": safe_mean(all_lengths),
            "Packet Length Std": safe_std(all_lengths),
            "Packet Length Variance": packet_length_variance,

            "FIN Flag Count": self.flag_counts["FIN"],
            "SYN Flag Count": self.flag_counts["SYN"],
            "RST Flag Count": self.flag_counts["RST"],
            "PSH Flag Count": self.flag_counts["PSH"],
            "ACK Flag Count": self.flag_counts["ACK"],
            "URG Flag Count": self.flag_counts["URG"],
            "CWE Flag Count": self.flag_counts["CWR"],
            "ECE Flag Count": self.flag_counts["ECE"],

            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            "Avg Fwd Segment Size": avg_fwd_segment_size,
            "Avg Bwd Segment Size": avg_bwd_segment_size,

            # Duplicate column present in the original dataset
            "Fwd Header Length.1": self.fwd_header_total,

            # ------------------------------------------------------------
            # STAGE 2: Bulk transfer features
            # ------------------------------------------------------------
            "Fwd Avg Bytes/Bulk": self._bulk_avg_bytes(self.fwd_bulks),
            "Fwd Avg Packets/Bulk": self._bulk_avg_packets(self.fwd_bulks),
            "Fwd Avg Bulk Rate": self._bulk_avg_rate(self.fwd_bulks),
            "Bwd Avg Bytes/Bulk": self._bulk_avg_bytes(self.bwd_bulks),
            "Bwd Avg Packets/Bulk": self._bulk_avg_packets(self.bwd_bulks),
            "Bwd Avg Bulk Rate": self._bulk_avg_rate(self.bwd_bulks),

            # Subflow features: CICFlowMeter resets these per-subflow, but
            # for flows with a single subflow (the common case), they equal
            # the totals.
            "Subflow Fwd Packets": total_fwd_packets,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Subflow Bwd Packets": total_bwd_packets,
            "Subflow Bwd Bytes": total_bwd_bytes,

            "Init_Win_bytes_forward": self.init_win_bytes_fwd if self.init_win_bytes_fwd is not None else 0,
            "Init_Win_bytes_backward": self.init_win_bytes_bwd if self.init_win_bytes_bwd is not None else 0,
            "act_data_pkt_fwd": self.act_data_pkt_fwd,
            "min_seg_size_forward": self.min_seg_size_fwd if self.min_seg_size_fwd is not None else 0,

            # ------------------------------------------------------------
            # STAGE 2: Active / Idle period features
            # CICFlowMeter expresses these in microseconds, like Flow Duration
            # ------------------------------------------------------------
            "Active Mean": safe_mean(self.active_durations) * 1_000_000,
            "Active Std": safe_std(self.active_durations) * 1_000_000,
            "Active Max": safe_max(self.active_durations) * 1_000_000,
            "Active Min": safe_min(self.active_durations) * 1_000_000,
            "Idle Mean": safe_mean(self.idle_durations) * 1_000_000,
            "Idle Std": safe_std(self.idle_durations) * 1_000_000,
            "Idle Max": safe_max(self.idle_durations) * 1_000_000,
            "Idle Min": safe_min(self.idle_durations) * 1_000_000,
        }

        return features

    # ------------------------------------------------------------------
    # Bulk feature helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bulk_avg_bytes(bulks):
        if not bulks:
            return 0.0
        return float(np.mean([b[1] for b in bulks]))

    @staticmethod
    def _bulk_avg_packets(bulks):
        if not bulks:
            return 0.0
        return float(np.mean([b[0] for b in bulks]))

    @staticmethod
    def _bulk_avg_rate(bulks):
        """Average bytes/second across bulks (0 if a bulk has 0 duration)."""
        if not bulks:
            return 0.0
        rates = []
        for packets, byte_count, duration in bulks:
            if duration > 0:
                rates.append(byte_count / duration)
            else:
                rates.append(0.0)
        return float(np.mean(rates))


# ----------------------------------------------------------------------
# Standalone test: build a synthetic flow and check feature values
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from scapy.all import Ether

    print("Building synthetic flow: 5 forward packets, 3 backward packets")
    flow = FlowRecord(
        src_ip="10.0.0.5", src_port=54321,
        dst_ip="10.0.0.10", dst_port=80,
        protocol=6, first_pkt_time=1000.0,
    )

    # Forward packets (client -> server), times 0, 0.1, 0.2, 0.3, 0.4
    for i in range(5):
        t = 1000.0 + i * 0.1
        flags = "S" if i == 0 else "PA"
        pkt = (
            Ether() /
            IP(src="10.0.0.5", dst="10.0.0.10") /
            TCP(sport=54321, dport=80, flags=flags, dataofs=5, window=29200) /
            (b"X" * (100 + i * 10))
        )
        flow.add_packet(pkt, t, "fwd")

    # Backward packets (server -> client), times 0.05, 0.15, 0.45
    for i, t in enumerate([1000.05, 1000.15, 1000.45]):
        flags = "SA" if i == 0 else "A"
        pkt = (
            Ether() /
            IP(src="10.0.0.10", dst="10.0.0.5") /
            TCP(sport=80, dport=54321, flags=flags, dataofs=5, window=64240) /
            (b"Y" * (200 + i * 20))
        )
        flow.add_packet(pkt, t, "bwd")

    features = flow.compute_features()

    print(f"\nFlow duration (us): {features['Flow Duration']:.1f}")
    print(f"Total Fwd Packets: {features['Total Fwd Packets']} (expected 5)")
    print(f"Total Bwd Packets: {features['Total Backward Packets']} (expected 3)")
    print(f"Total Length of Fwd Packets: {features['Total Length of Fwd Packets']}")
    print(f"Total Length of Bwd Packets: {features['Total Length of Bwd Packets']}")
    print(f"Fwd Packet Length Mean: {features['Fwd Packet Length Mean']:.2f}")
    print(f"Bwd Packet Length Mean: {features['Bwd Packet Length Mean']:.2f}")
    print(f"Flow Bytes/s: {features['Flow Bytes/s']:.2f}")
    print(f"Flow Packets/s: {features['Flow Packets/s']:.2f}")
    print(f"Flow IAT Mean: {features['Flow IAT Mean']:.6f}")
    print(f"SYN Flag Count: {features['SYN Flag Count']} (expected 2: one fwd SYN, one bwd SYN-ACK)")
    print(f"ACK Flag Count: {features['ACK Flag Count']} (expected 7: 4 fwd PA + 1 bwd SA + 2 bwd A)")
    print(f"PSH Flag Count: {features['PSH Flag Count']} (expected 4: 4 fwd PA packets)")
    print(f"Down/Up Ratio: {features['Down/Up Ratio']:.3f} (expected 0.6 = 3/5)")
    print(f"Avg Fwd Segment Size: {features['Avg Fwd Segment Size']:.2f}")
    print(f"Avg Bwd Segment Size: {features['Avg Bwd Segment Size']:.2f}")

    print(f"\nInit_Win_bytes_forward: {features['Init_Win_bytes_forward']} (expected 29200)")
    print(f"Init_Win_bytes_backward: {features['Init_Win_bytes_backward']} (expected 64240)")
    print(f"act_data_pkt_fwd: {features['act_data_pkt_fwd']} (expected 4: SYN has no payload, 4 PA packets do)")
    print(f"min_seg_size_forward: {features['min_seg_size_forward']} (expected 40: 20 IP + 20 TCP header)")

    print(f"\nActive Mean (us): {features['Active Mean']:.1f} (expected ~450000, one continuous burst)")
    print(f"Idle Mean (us): {features['Idle Mean']:.1f} (expected 0, no gaps > 1s)")
    print(f"Fwd Avg Packets/Bulk: {features['Fwd Avg Packets/Bulk']} (expected 4: one bulk of the 4 PA packets)")
    print(f"Fwd Avg Bytes/Bulk: {features['Fwd Avg Bytes/Bulk']}")

    print(f"\nTotal feature count: {len(features)} (expected 78)")
    expected_keys = 78
    if len(features) != expected_keys:
        print(f"WARNING: feature count mismatch! Got {len(features)}, expected {expected_keys}")
    else:
        print("Feature count matches expected 78.")

    print("\nAll feature names:")
    for k in features:
        print(f"  {k}")

    # ------------------------------------------------------------------
    # Second scenario: idle gap + bulk transfer to exercise Active/Idle
    # and Bulk features more directly.
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("Scenario 2: idle gap + clean bulk transfer")
    print("=" * 60)

    flow2 = FlowRecord(
        src_ip="10.0.0.5", src_port=55000,
        dst_ip="10.0.0.20", dst_port=443,
        protocol=6, first_pkt_time=2000.0,
    )

    # Burst 1: 2 forward packets close together (active period 1)
    for i, t in enumerate([2000.0, 2000.05]):
        pkt = (
            Ether() / IP(src="10.0.0.5", dst="10.0.0.20") /
            TCP(sport=55000, dport=443, flags="PA", dataofs=5, window=29200) /
            (b"A" * 50)
        )
        flow2.add_packet(pkt, t, "fwd")

    # Idle gap of 3 seconds (> 1s threshold) -> closes active period 1,
    # records a 3s idle gap, starts active period 2
    # Burst 2: 6 forward packets close together, all with payload -> 1 bulk
    burst2_start = 2003.0
    for i in range(6):
        t = burst2_start + i * 0.01
        pkt = (
            Ether() / IP(src="10.0.0.5", dst="10.0.0.20") /
            TCP(sport=55000, dport=443, flags="PA", dataofs=5, window=29200) /
            (b"B" * 500)
        )
        flow2.add_packet(pkt, t, "fwd")

    features2 = flow2.compute_features()

    print(f"\nActive durations (s): {[round(d, 3) for d in flow2.active_durations]}")
    print(f"  (expected ~2 periods: [~0.05, ~0.05] for the two bursts)")
    print(f"Idle durations (s): {[round(d, 3) for d in flow2.idle_durations]}")
    print(f"  (expected 1 gap: [~3.0])")
    print(f"Active Mean (us): {features2['Active Mean']:.1f}")
    print(f"Idle Mean (us): {features2['Idle Mean']:.1f} (expected ~3000000)")

    print(f"\nFwd bulks detected: {flow2.fwd_bulks}")
    print(f"  (expected 1 bulk: 6 packets, 3000 bytes, ~0.05s duration)")
    print(f"Fwd Avg Packets/Bulk: {features2['Fwd Avg Packets/Bulk']} (expected 6.0)")
    print(f"Fwd Avg Bytes/Bulk: {features2['Fwd Avg Bytes/Bulk']} (expected 3000.0)")
    print(f"Fwd Avg Bulk Rate: {features2['Fwd Avg Bulk Rate']:.2f} (bytes/sec)")
