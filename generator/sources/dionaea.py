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
    # 一部はマルウェア検体ダウンロードに発展（本物のハッシュ/URL/ドメインを出力）
    ioc = corpus.pick_file_ioc() if random.random() < 0.15 else None
    if ioc:
        ev["eventid"] = "dionaea.download.complete"
        dl = {"md5_hash": ioc.get("md5", ""),
              "sha256_hash": ioc.get("sha256", ""),
              "url": ioc.get("url", ""),
              "filename": ioc.get("filename", "")}
        # URL からドメイン(host)を補完
        host = ioc.get("domain") or _host_from_url(ioc.get("url", ""))
        if host:
            dl["host"] = host
        ev["download"] = {k: v for k, v in dl.items() if v}
    else:
        ev["eventid"] = "dionaea.connection"
    return schema.SOURCETYPE_MAP["dionaea"], ev


def _host_from_url(url: str) -> str:
    """http://host/path → host（ポート除去）。"""
    if "://" not in url:
        return ""
    rest = url.split("://", 1)[1]
    return rest.split("/", 1)[0].split(":", 1)[0]
