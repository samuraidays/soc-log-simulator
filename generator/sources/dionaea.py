"""Dionaea(SMB/マルウェア捕獲) のネイティブ生イベント生成。"""
from __future__ import annotations

import random

from .. import schema


def generate(corpus, ip_rec: dict, dst_ip: str) -> tuple[str, dict]:
    d = corpus.dionaea
    epoch = schema.now_epoch()
    dst_port = random.choice(d.get("dst_ports", [445]))
    proto = "smbd" if dst_port in (445, 139) else random.choice(d["protocols"])
    ev = {
        "src_ip": ip_rec["ip"],
        "src_port": schema.ephemeral_port(),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "connection": {"protocol": proto, "transport": "tcp", "type": "accept"},
        "sensor": d.get("sensor", "tpot-sensor-01"),
        "timestamp": schema.iso_utc(epoch),
    }
    # 一部はマルウェア検体ダウンロードに発展
    if random.random() < 0.15:
        dl = random.choice(d["downloads"])
        ev["eventid"] = "dionaea.download.complete"
        ev["download"] = {"md5_hash": dl["md5"], "url": dl["url"], "filename": dl["filename"]}
    else:
        ev["eventid"] = "dionaea.connection"
    return schema.SOURCETYPE_MAP["dionaea"], ev
