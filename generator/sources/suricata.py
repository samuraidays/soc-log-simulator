"""Suricata(IDS) のネイティブ EVE alert イベント生成。"""
from __future__ import annotations

import random

from .. import schema


def generate(corpus, ip_rec: dict, dst_ip: str, benign: bool = False) -> tuple[str, dict]:
    s = corpus.suricata
    epoch = schema.now_epoch()
    sigs = s["benign_signatures"] if benign else s["malicious_signatures"]
    sig = random.choice(sigs)
    dst_port = random.choice([22, 445, 80, 443, 23, 8080])
    ev = {
        "timestamp": schema.iso_utc(epoch),
        "flow_id": schema.flow_id(),
        "event_type": "alert",
        "src_ip": ip_rec["ip"],
        "src_port": schema.ephemeral_port(),
        "dest_ip": dst_ip,
        "dest_port": dst_port,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature": sig["signature"],
            "signature_id": sig["signature_id"],
            "category": sig["category"],
            "severity": sig["severity"],
        },
        "sensor": s.get("sensor", "tpot-sensor-01"),
    }
    return schema.SOURCETYPE_MAP["suricata"], ev
