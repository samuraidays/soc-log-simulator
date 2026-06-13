"""Cowrie(SSH ハニーポット) のネイティブ生イベント生成。

実際の cowrie.json は eventid ベースの行イベント。ここでは login.failed /
command.input / session.connect を実観測値から生成する。エンリッチは付けない。
"""
from __future__ import annotations

import random

from .. import schema


def generate(corpus, ip_rec: dict, dst_ip: str) -> tuple[str, dict]:
    c = corpus.cowrie
    epoch = schema.now_epoch()
    base = {
        "src_ip": ip_rec["ip"],
        "src_port": schema.ephemeral_port(),
        "dst_ip": dst_ip,
        "dst_port": 22,
        "session": schema.session_id(),
        "protocol": "ssh",
        "sensor": c.get("sensor", "tpot-sensor-01"),
        "timestamp": schema.iso_utc(epoch),
    }

    roll = random.random()
    if roll < 0.6:
        # 認証失敗（ブルートフォースの大半）
        base.update({
            "eventid": "cowrie.login.failed",
            "username": random.choice(c["usernames"]),
            "password": random.choice(c["passwords"]),
            "message": "login attempt [{}/{}] failed".format(
                base.get("username", ""), "***"),
        })
    elif roll < 0.75:
        # 認証成功（一部のIPが侵入に成功）
        base.update({
            "eventid": "cowrie.login.success",
            "username": random.choice(c["usernames"]),
            "password": random.choice(c["passwords"]),
            "message": "login attempt succeeded",
        })
    elif roll < 0.95:
        # コマンド入力（recon / バックドア注入チェーン）
        cmd = random.choice(c["commands"])
        base.update({
            "eventid": "cowrie.command.input",
            "input": cmd,
            "message": "CMD: {}".format(cmd),
        })
    else:
        base.update({
            "eventid": "cowrie.session.connect",
            "message": "New connection: {}:{}".format(base["src_ip"], base["src_port"]),
        })

    # username/password を message に正しく埋める（login.failed の体裁）
    if base["eventid"] == "cowrie.login.failed":
        base["message"] = "login attempt [{}/{}] failed".format(base["username"], base["password"])

    return schema.SOURCETYPE_MAP["cowrie"], base
