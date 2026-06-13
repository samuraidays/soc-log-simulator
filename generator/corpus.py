"""コーパス（実データ由来シード）のロードとアクセス。"""
from __future__ import annotations

import json
import random
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus"


class Corpus:
    """corpus/*.json をまとめて読み込み、サンプリングを提供する。"""

    def __init__(self, corpus_dir: Path = CORPUS_DIR):
        self.dir = Path(corpus_dir)
        self.malicious_ips = self._load("malicious_ips.json")["ips"]
        self.benign_ips = self._load("benign_ips.json")["ips"]
        self.cowrie = self._load("cowrie_events.json")
        self.dionaea = self._load("dionaea_events.json")
        self.suricata = self._load("suricata_events.json")
        self.tanner = self._load("tanner_events.json")
        self.timeline = self._load("timeline_profile.json")

    def _load(self, name: str) -> dict:
        with open(self.dir / name, encoding="utf-8") as f:
            return json.load(f)

    # --- IP 選択（src_ip は実IOCのまま。相関を発火させるため変異させない） ---
    def pick_malicious_ip(self, kind: str | None = None) -> dict:
        pool = self.malicious_ips
        if kind:
            filtered = [ip for ip in pool if ip.get("kind") == kind]
            pool = filtered or pool
        return random.choice(pool)

    def pick_benign_ip(self) -> dict:
        return random.choice(self.benign_ips)

    def __repr__(self) -> str:
        return (
            f"<Corpus malicious={len(self.malicious_ips)} benign={len(self.benign_ips)} "
            f"cmds={len(self.cowrie.get('commands', []))}>"
        )
