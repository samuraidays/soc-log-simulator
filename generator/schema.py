"""共有のイベント構築ヘルパー。

各ハニーポットの「生ログ（エンリッチ前）」を組み立てるための共通部品を提供する。
ここでは abuse_score / gn_classification といったエンリッチ値は一切付けない —
それは CTI 製品が後段で付与する部分であり、本シミュレータの責務ではない。
"""
from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timezone

# honeypot 種別 -> Splunk sourcetype（Splunk の TA と整合する標準的な名前）
SOURCETYPE_MAP = {
    "cowrie": "cowrie",
    "dionaea": "dionaea",
    "suricata": "suricata:eve",
    "tanner": "tanner",
}


def now_epoch() -> float:
    """現在時刻（HEC の time フィールド用 epoch 秒）。"""
    return time.time()


def iso_utc(epoch: float | None = None) -> str:
    """Cowrie/Suricata 互換の ISO8601(UTC, ミリ秒) 文字列。"""
    ts = epoch if epoch is not None else now_epoch()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ephemeral_port() -> int:
    """攻撃元の高位ランダムポート（毎イベントで変異）。"""
    return random.randint(1024, 65535)


def session_id() -> str:
    """Cowrie セッションID 風の 12 桁 hex。"""
    return uuid.uuid4().hex[:12]


def flow_id() -> int:
    """Suricata flow_id 風の整数。"""
    return random.randint(1_000_000_000_000, 9_999_999_999_999)
