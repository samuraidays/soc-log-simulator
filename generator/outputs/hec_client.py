"""Splunk HTTP Event Collector(HEC) 送信。標準ライブラリ(urllib)のみ。"""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request


class HECClient:
    def __init__(self, config: dict):
        hec = config.get("hec", {})
        self.url = hec.get("url", "https://localhost:8088").rstrip("/") + "/services/collector/event"
        self.token = hec.get("token", "")
        self.index = hec.get("index", "main")
        self.host = hec.get("host", "tpot-sim")
        self.batch_size = int(hec.get("batch_size", 50))
        self.timeout = float(hec.get("timeout", 10))
        verify = hec.get("verify_tls", False)
        self._ctx = None if verify else ssl._create_unverified_context()
        # sourcetype をSplunkのTAに合わせて上書きしたい場合は config.sourcetype_map で指定
        self.smap = config.get("sourcetype_map", {}) or {}
        self._buf: list[str] = []

    def _envelope(self, sourcetype: str, event: dict, epoch: float | None) -> str:
        env = {
            "event": event,
            "sourcetype": self.smap.get(sourcetype, sourcetype),
            "index": self.index,
            "host": self.host,
            "source": "tpot-sim",
        }
        if epoch is not None:
            env["time"] = epoch
        return json.dumps(env, ensure_ascii=False)

    def add(self, sourcetype: str, event: dict, epoch: float | None = None):
        self._buf.append(self._envelope(sourcetype, event, epoch))
        if len(self._buf) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self._buf:
            return
        # HEC は1リクエストに連続したJSONオブジェクトを受理する
        data = "\n".join(self._buf).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                    resp.read()
                self._buf.clear()
                return
            except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
                if attempt == 2:
                    raise RuntimeError(f"HEC送信失敗: {e}") from e
                time.sleep(1.5 * (attempt + 1))

    def close(self):
        self.flush()
