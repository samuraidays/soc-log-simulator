#!/usr/bin/env python3
"""T-POT 攻撃ログ・シミュレータ本体。

実IOCに基づく「生ログ（エンリッチ前）」＋良性ノイズを生成し、Splunk HEC へ常時供給する。
エンリッチ（レピュテーション/分類）は CTI 製品が後段で付与する前提のため、ここでは付けない。

使い方:
  python3 run.py                 # 連続供給（Ctrl-C / SIGTERM で安全停止）
  python3 run.py --once          # 1件だけ送って終了（疎通確認）
  python3 run.py --dry-run       # 送信せず標準出力に整形表示（フォーマット確認）
  python3 run.py --replay-speed 10   # 時間を10倍速で圧縮（デモ用に大量生成）
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from generator.corpus import Corpus
from generator.sampler import Sampler
from generator.schema import now_epoch
from generator.timeline import Timeline

ROOT = Path(__file__).resolve().parent


class StdoutEmitter:
    """--dry-run 用。送信せず1行JSONで標準出力に出す。"""

    def add(self, sourcetype, event, epoch=None):
        print(json.dumps({"sourcetype": sourcetype, "event": event}, ensure_ascii=False))

    def flush(self):
        sys.stdout.flush()

    def close(self):
        self.flush()


def _deep_merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: Path) -> dict:
    """config.json を読み、隣の config.local.json（gitignore対象）で上書きする。

    機密（HECトークン）や環境固有値（url/index）は config.local.json または
    環境変数 SPLUNK_HEC_TOKEN に置く。これらはリポジトリにコミットされない。
    """
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
    local = path.with_name("config.local.json")
    if local.exists():
        with open(local, encoding="utf-8") as f:
            _deep_merge(config, json.load(f))
    env_token = os.environ.get("SPLUNK_HEC_TOKEN")
    if env_token:
        config.setdefault("hec", {})["token"] = env_token
    return config


def build_emitter(config: dict, dry_run: bool):
    if dry_run:
        return StdoutEmitter()
    if config.get("output") == "file":
        from generator.outputs.file_emitter import FileEmitter
        return FileEmitter(config)
    from generator.outputs.hec_client import HECClient
    return HECClient(config)


def main() -> int:
    ap = argparse.ArgumentParser(description="T-POT attack log simulator -> Splunk")
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--once", action="store_true", help="1件だけ送って終了")
    ap.add_argument("--dry-run", action="store_true", help="送信せず標準出力に表示")
    ap.add_argument("--replay-speed", type=float, default=1.0, help="時間圧縮係数(>1で高速)")
    args = ap.parse_args()

    config = load_config(Path(args.config))
    corpus = Corpus()
    sampler = Sampler(corpus, config)
    timeline = Timeline(corpus.timeline, base_eps=float(config.get("eps", 5)),
                        replay_speed=args.replay_speed)
    emitter = build_emitter(config, args.dry_run)

    running = {"on": True}

    def _stop(signum, frame):
        running["on"] = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    sent = 0
    errors = 0
    last_report = time.time()
    try:
        while running["on"]:
            result = sampler.next_event()
            if result is None:
                sys.stderr.write("enabled_sources が空か該当源なし。config を確認してください。\n")
                break
            sourcetype, event = result

            try:
                emitter.add(sourcetype, event, epoch=now_epoch())
                sent += 1
            except Exception as e:  # noqa: BLE001
                # --once（疎通確認）では失敗を表面化。連続供給では Splunk の一時停止で
                # 死なないよう、ログだけ出して継続（systemd の Restart にも頼れる）。
                if args.once:
                    raise
                errors += 1
                sys.stderr.write(f"[sim] 送信エラー(継続します): {e}\n")
                sys.stderr.flush()
                time.sleep(2)

            if args.once:
                break

            # 進捗を10秒ごとに stderr へ
            now = time.time()
            if now - last_report >= 10:
                try:
                    emitter.flush()
                except Exception as e:  # noqa: BLE001
                    errors += 1
                    sys.stderr.write(f"[sim] flushエラー(継続します): {e}\n")
                sys.stderr.write(f"[sim] sent={sent} errors={errors} eps={timeline.current_eps():.1f}\n")
                sys.stderr.flush()
                last_report = now

            time.sleep(timeline.sleep_seconds())
    finally:
        try:
            emitter.close()
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[sim] 終了flushエラー: {e}\n")
        sys.stderr.write(f"[sim] stopped. total sent={sent} errors={errors}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
