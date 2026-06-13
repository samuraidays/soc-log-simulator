"""Tanner(Web/HTTP ハニーポット) のネイティブ生イベント生成。

Tanner は送信元を peer.ip で表す（src_ip ではない）点に注意。
"""
from __future__ import annotations

import random

from .. import schema


def generate(corpus, ip_rec: dict, dst_ip: str, benign: bool = False) -> tuple[str, dict]:
    t = corpus.tanner
    epoch = schema.now_epoch()
    paths = t["benign_paths"] if benign else t["malicious_paths"]
    p = random.choice(paths)
    ev = {
        "timestamp": schema.iso_utc(epoch),
        "peer": {"ip": ip_rec["ip"], "port": schema.ephemeral_port()},
        "method": p["method"],
        "path": p["path"],
        "status": 200,
        "headers": {"user-agent": p["user_agent"], "host": dst_ip},
        "uuid": schema.session_id(),
        "sensor": t.get("sensor", "tpot-sensor-01"),
    }
    return schema.SOURCETYPE_MAP["tanner"], ev
