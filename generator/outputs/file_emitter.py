"""JSON Lines をファイルに追記する出力（Splunk forwarder / file monitor 用）。

honeypot 種別ごとにファイルを分け、本物の T-POT ログ配置を模倣する。
HEC が使えない環境のフォールバック。
"""
from __future__ import annotations

import json
from pathlib import Path


class FileEmitter:
    def __init__(self, config: dict):
        fcfg = config.get("file", {})
        self.dir = Path(fcfg.get("output_dir", "./out"))
        self.dir.mkdir(parents=True, exist_ok=True)
        self._handles: dict[str, object] = {}
        # sourcetype -> ファイル名
        self._names = {
            "cowrie": "cowrie.json",
            "dionaea": "dionaea.json",
            "suricata:eve": "eve.json",
            "tanner": "tanner_report.json",
        }

    def _handle(self, sourcetype: str):
        if sourcetype not in self._handles:
            name = self._names.get(sourcetype, sourcetype.replace(":", "_") + ".json")
            self._handles[sourcetype] = open(self.dir / name, "a", encoding="utf-8")
        return self._handles[sourcetype]

    def add(self, sourcetype: str, event: dict, epoch: float | None = None):
        fh = self._handle(sourcetype)
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    def flush(self):
        for fh in self._handles.values():
            fh.flush()

    def close(self):
        self.flush()
        for fh in self._handles.values():
            fh.close()
        self._handles.clear()
