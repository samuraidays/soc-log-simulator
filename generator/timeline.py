"""時間帯プロファイルに沿った発火レート制御。"""
from __future__ import annotations

from datetime import datetime, timezone


class Timeline:
    """設定 EPS に時間帯/曜日の重みを掛けて、現在の目標 EPS を返す。"""

    def __init__(self, profile: dict, base_eps: float, replay_speed: float = 1.0):
        self.hour_weights = profile.get("hour_weights_utc", [1.0] * 24)
        self.weekday_weights = profile.get("weekday_weights", [1.0] * 7)
        self.base_eps = base_eps
        self.replay_speed = max(0.01, replay_speed)

    def current_eps(self, now: datetime | None = None) -> float:
        now = now or datetime.now(timezone.utc)
        hw = self.hour_weights[now.hour % 24]
        ww = self.weekday_weights[now.weekday() % 7]
        return self.base_eps * hw * ww * self.replay_speed

    def sleep_seconds(self, now: datetime | None = None) -> float:
        """1イベント発火あたりの待機秒。EPS<=0 の場合は1秒で間引く。"""
        eps = self.current_eps(now)
        if eps <= 0:
            return 1.0
        return 1.0 / eps
