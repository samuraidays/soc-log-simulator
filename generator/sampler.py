"""イベント選択ロジック: 悪性/良性の比率に従い、適切なハニーポット源へ振り分ける。"""
from __future__ import annotations

import random

from .sources import cowrie, dionaea, suricata, tanner


class Sampler:
    def __init__(self, corpus, config: dict):
        self.corpus = corpus
        self.dst_ip = config.get("dst_ip", "10.0.0.10")
        self.enabled = set(config.get("enabled_sources", ["cowrie", "dionaea", "suricata", "tanner"]))
        # malicious_benign_ratio: [malicious, benign] の相対比（例 [1, 4]）
        ratio = config.get("malicious_benign_ratio", [1, 4])
        self.p_malicious = ratio[0] / float(ratio[0] + ratio[1])

    def _src_enabled(self, name: str) -> bool:
        return name in self.enabled

    def next_event(self) -> tuple[str, dict] | None:
        """次の (sourcetype, event) を1件返す。enabled に該当源が無ければ None。"""
        if random.random() < self.p_malicious:
            return self._malicious()
        return self._benign()

    def _malicious(self) -> tuple[str, dict] | None:
        ip = self.corpus.pick_malicious_ip()
        kind = ip.get("kind", "ssh-bruteforce")
        if kind == "ssh-bruteforce":
            # 大半は cowrie、たまに suricata の SSH 系アラート
            if self._src_enabled("cowrie") and random.random() < 0.85:
                return cowrie.generate(self.corpus, ip, self.dst_ip)
            if self._src_enabled("suricata"):
                return suricata.generate(self.corpus, ip, self.dst_ip, benign=False)
            if self._src_enabled("cowrie"):
                return cowrie.generate(self.corpus, ip, self.dst_ip)
        else:  # smb-scan
            if self._src_enabled("dionaea") and random.random() < 0.8:
                return dionaea.generate(self.corpus, ip, self.dst_ip)
            if self._src_enabled("suricata"):
                return suricata.generate(self.corpus, ip, self.dst_ip, benign=False)
            if self._src_enabled("dionaea"):
                return dionaea.generate(self.corpus, ip, self.dst_ip)
        return self._any_malicious_fallback(ip)

    def _any_malicious_fallback(self, ip) -> tuple[str, dict] | None:
        for name, fn in (("cowrie", cowrie), ("dionaea", dionaea), ("suricata", suricata)):
            if self._src_enabled(name):
                if name == "suricata":
                    return fn.generate(self.corpus, ip, self.dst_ip, benign=False)
                return fn.generate(self.corpus, ip, self.dst_ip)
        return None

    def _benign(self) -> tuple[str, dict] | None:
        ip = self.corpus.pick_benign_ip()
        # 良性スキャナは Web クロール/IDS info/SSHタッチに散らす
        choices = []
        if self._src_enabled("tanner"):
            choices.append(("tanner", lambda: tanner.generate(self.corpus, ip, self.dst_ip, benign=True)))
        if self._src_enabled("suricata"):
            choices.append(("suricata", lambda: suricata.generate(self.corpus, ip, self.dst_ip, benign=True)))
        if self._src_enabled("cowrie"):
            choices.append(("cowrie", lambda: cowrie.generate(self.corpus, ip, self.dst_ip)))
        if not choices:
            return None
        return random.choice(choices)[1]()
