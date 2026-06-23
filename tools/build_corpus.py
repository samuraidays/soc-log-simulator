#!/usr/bin/env python3
"""build_corpus — 運用中 T-POT の生ログから corpus/ を再生成する（環境A用）。

このツールはプライベート側（T-POT/Wazuh にアクセスできる環境）で時々実行する。
生成した corpus/ を会社のSplunkサーバ（環境B）へコピーすれば、シミュレータは
T-POT/Wazuh に一切接続せず自己完結で動く。

重要: 生ログ（エンリッチ前）を読む。Wazuh(wazuh-alerts-*)はエンリッチ後なので使わない。
生ログは T-POT VPS の enrichment コンテナ内 /logs/... にあり（パイプラインの入力）、
docker compose exec でコンテナに入って読む（ホスト直下には存在しない）。

入力（いずれか）:
  --ssh-host HOST   T-POT VPS へ SSH し、enrichment コンテナの /logs/... を読む。
                    例: --ssh-host tpot （INFRA.md: Wazuhサーバ wazuh とは別ホスト）
                    補助: --compose-dir(既定 ~/tpotce) / --service(既定 enrichment_pipeline)
  --src-dir DIR     SSH を使わず、手動で取得した生ログ群を読む（cowrie.json,
                    dionaea.json, eve.json, tanner_report.json, 任意で honeypot_enriched.json）

出力:
  corpus/*.json を上書き（--out で出力先変更可、既定はリポジトリの corpus/）

honeypot_enriched.json があれば src_ip の国/ISP/良性悪性分類も取り込む（これは唯一の
エンリッチ済みソースだが、IP仕分けにのみ使い生成イベントには埋め込まない）。無ければ
生ログだけで commands/paths/signatures/usernames を更新し、IP分類はヒューリスティックで行う。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

# enrichment コンテナ内のパス（enrichment_pipeline.py の LOG_FILES / OUTPUT_DIR と一致）。
# これらは T-POT ホストのファイルシステムには存在せず、コンテナ内にだけ存在する。
# そのため ssh 経由では `docker compose exec` でコンテナに入って読む（パス推測が不要）。
# 注意: ここは生ログ（エンリッチ前）。Wazuh(wazuh-alerts-*) はエンリッチ後なので使わない。
CONTAINER_LOGS = {
    "cowrie": "/logs/cowrie/cowrie.json",
    "dionaea": "/logs/dionaea/dionaea.json",
    "tanner": "/logs/tanner/tanner_report.json",
    "suricata": "/logs/suricata/eve.json",
    # enriched だけは唯一のエンリッチ済みソース。IPの良性悪性分類/国/ISPの取得にのみ使い、
    # 生成イベントには一切埋め込まない（イベントは生ログのまま）。無くても他は更新可能。
    "enriched": "/output/honeypot_enriched.json",
}
LOCAL_NAMES = {
    "cowrie": "cowrie.json",
    "dionaea": "dionaea.json",
    "tanner": "tanner_report.json",
    "suricata": "eve.json",
    "enriched": "honeypot_enriched.json",
}

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_URL_RE = re.compile(r"https?://[^\s'\"|;>)]+", re.IGNORECASE)


def host_from_url(url: str) -> str:
    if "://" not in url:
        return ""
    return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]


def sanitize(s: str, max_len: int = 200) -> str:
    """攻撃者制御文字列のサニタイズ（制御文字除去・長さ制限）。"""
    return _CTRL.sub(" ", str(s)).strip()[:max_len]


def read_lines(source: str, args, tail: int) -> list[dict]:
    """指定ソースの生ログを最大 tail 行読み、JSON行をパースして返す。"""
    raw = ""
    if args.ssh_host:
        # T-POT VPS へ SSH → enrichment コンテナ内の /logs を docker compose exec で読む。
        # パイプラインと同じマウントを使うのでパスのズレが起きない。
        path = CONTAINER_LOGS[source]
        remote = (
            f"cd {args.compose_dir} && "
            f"docker compose exec -T {args.service} tail -n {tail} {path} 2>/dev/null"
        )
        try:
            raw = subprocess.run(
                ["ssh", args.ssh_host, remote],
                capture_output=True, text=True, timeout=120,
            ).stdout
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[warn] {source} 取得失敗: {e}\n")
            return []
    else:
        p = Path(args.src_dir) / LOCAL_NAMES[source]
        if not p.exists():
            sys.stderr.write(f"[warn] {p} が無いのでスキップ\n")
            return []
        raw = p.read_text(encoding="utf-8", errors="replace")
        raw = "\n".join(raw.splitlines()[-tail:])

    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def top_keys(counter: Counter, n: int) -> list:
    return [k for k, _ in counter.most_common(n) if k]


def build(args) -> dict:
    out = {}
    # マルウェアIOC（全ソース横断で集約）。file_iocs=ハッシュ系 / url_iocs=ネットワーク系
    file_iocs: dict = {}
    url_iocs: dict = {}

    # --- cowrie ---
    rows = read_lines("cowrie", args, args.tail)
    if rows:
        users, pws, cmds, ips = Counter(), Counter(), Counter(), Counter()
        for r in rows:
            if r.get("username"):
                users[r["username"]] += 1
            if r.get("password"):
                pws[r["password"]] += 1
            if r.get("input"):
                cmds[sanitize(r["input"])] += 1
                # wget/curl 等のコマンドから本物のマルウェアURL/ドメインを抽出
                for u in _URL_RE.findall(r["input"]):
                    u = sanitize(u, 200)
                    url_iocs[u] = {"url": u, "domain": host_from_url(u)}
            if r.get("src_ip"):
                ips[r["src_ip"]] += 1
        existing = json.loads((CORPUS / "cowrie_events.json").read_text())
        existing["usernames"] = top_keys(users, 40) or existing["usernames"]
        existing["passwords"] = top_keys(pws, 30) or existing["passwords"]
        existing["commands"] = top_keys(cmds, 40) or existing["commands"]
        out["cowrie_events.json"] = existing
        out["_cowrie_ips"] = ips

    # --- suricata ---
    rows = read_lines("suricata", args, args.tail)
    if rows:
        mal, ben = {}, {}
        for r in rows:
            if r.get("event_type") != "alert":
                continue
            a = r.get("alert", {})
            sig = a.get("signature")
            if not sig:
                continue
            sev = a.get("severity", 3)
            rec = {"signature": sig, "category": a.get("category", ""),
                   "signature_id": a.get("signature_id", 0), "severity": sev}
            (ben if sev >= 3 else mal)[sig] = rec
        existing = json.loads((CORPUS / "suricata_events.json").read_text())
        if mal:
            existing["malicious_signatures"] = list(mal.values())[:20]
        if ben:
            existing["benign_signatures"] = list(ben.values())[:20]
        out["suricata_events.json"] = existing

    # --- tanner ---
    rows = read_lines("tanner", args, args.tail)
    if rows:
        paths = {}
        for r in rows:
            path = r.get("path")
            if not path:
                continue
            paths[path] = {"method": r.get("method", "GET"), "path": sanitize(path, 120),
                           "user_agent": sanitize((r.get("headers", {}) or {}).get("user-agent", "-"), 120)}
        existing = json.loads((CORPUS / "tanner_events.json").read_text())
        if paths:
            existing["malicious_paths"] = list(paths.values())[:20]
        out["tanner_events.json"] = existing

    # --- dionaea ---
    rows = read_lines("dionaea", args, args.tail)
    if rows:
        ports = Counter()
        for r in rows:
            dp = r.get("dst_port")
            if dp:
                ports[dp] += 1
            dl = r.get("download") or {}
            md5 = dl.get("md5_hash") or r.get("download_md5")
            sha = dl.get("sha256_hash") or dl.get("sha256")
            url = sanitize(dl.get("url", r.get("download_url", "")), 200)
            if md5 or sha:
                key = sha or md5
                file_iocs[key] = {"md5": md5 or "", "sha256": sha or "",
                                  "url": url, "domain": host_from_url(url),
                                  "filename": sanitize(dl.get("filename", ""), 60)}
        existing = json.loads((CORPUS / "dionaea_events.json").read_text())
        if ports:
            existing["dst_ports"] = [p for p, _ in ports.most_common(6)]
        out["dionaea_events.json"] = existing

    # --- enriched（あれば IP分類 + 実マルウェアハッシュ を更新） ---
    # 唯一のエンリッチ済みソース。GreyNoise分類で良性/悪性のIPを仕分け、
    # VT(GTI)確定済みの実md5+vt_familyを取り込む。これらは GTI/GreyNoise が
    # 実際に照会して反応する「使えるデータ」になる（ダミーではなく実観測値）。
    rows = read_lines("enriched", args, args.tail * 4)
    if rows:
        mal_ips, ben_ips = {}, {}
        for r in rows:
            ip = r.get("src_ip") or (r.get("peer", {}) or {}).get("ip")
            enr = r.get("enrichment", {}) or {}
            isp = enr.get("abuse_isp", "")
            country = enr.get("abuse_country", "")
            cls = enr.get("gn_classification")
            src = r.get("honeypot_source", "")

            # IP の仕分け
            if ip:
                if cls == "benign":
                    ben_ips[ip] = {"ip": ip, "country": country, "isp": isp, "kind": "scanner"}
                elif enr.get("abuse_score", 0) and enr["abuse_score"] >= 50:
                    kind = "smb-scan" if src == "dionaea" else "ssh-bruteforce"
                    mal_ips[ip] = {"ip": ip, "country": country, "isp": isp, "kind": kind}

            # VT確定済みの実マルウェアハッシュ（GTIが反応するもののみ採用、sha256も取得）
            dl = r.get("download", {}) or {}
            md5 = r.get("download_md5") or dl.get("md5_hash")
            sha = dl.get("sha256_hash") or dl.get("sha256") or r.get("download_sha256")
            if (md5 or sha) and enr.get("vt_malicious", 0):
                url = sanitize(r.get("download_url", dl.get("url", "")), 200)
                key = sha or md5
                file_iocs[key] = {"md5": md5 or "", "sha256": sha or "",
                                  "url": url, "domain": host_from_url(url),
                                  "filename": sanitize(dl.get("filename", ""), 60),
                                  "vt_family": sanitize(enr.get("vt_family", ""), 60)}

        if mal_ips:
            out["malicious_ips.json"] = {"_comment": "build_corpus.py により再生成",
                                         "ips": list(mal_ips.values())[:60]}
        if ben_ips:
            out["benign_ips.json"] = {"_comment": "build_corpus.py により再生成（GreyNoise=benign）",
                                      "ips": list(ben_ips.values())[:30]}

    # --- malware_iocs.json にマージ（フィード(import_iocs)由来やEICARを保持） ---
    if file_iocs or url_iocs:
        doc = json.loads((CORPUS / "malware_iocs.json").read_text())
        existing = doc.get("iocs", [])

        def _k(i: dict) -> str:
            return i.get("sha256") or i.get("md5") or i.get("url") or i.get("domain") or ""

        seen = {_k(i) for i in existing if _k(i)}
        for i in list(file_iocs.values())[:30] + list(url_iocs.values())[:30]:
            k = _k(i)
            if k and k not in seen:
                seen.add(k)
                existing.append({kk: vv for kk, vv in i.items() if vv})
        doc["iocs"] = existing
        out["malware_iocs.json"] = doc

    out.pop("_cowrie_ips", None)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="T-POT 生ログから corpus/ を再生成")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--src-dir", help="生ログを置いたローカルディレクトリ（手動取得した場合）")
    g.add_argument("--ssh-host", help="T-POT VPS への SSH ホスト名（例: tpot。Wazuhサーバではない）")
    ap.add_argument("--compose-dir", default="~/tpotce",
                    help="T-POT の docker compose プロジェクトディレクトリ（既定: ~/tpotce）")
    ap.add_argument("--service", default="enrichment_pipeline",
                    help="生ログをマウントしている compose サービス名（既定: enrichment_pipeline）")
    ap.add_argument("--out", default=str(CORPUS), help="出力先（既定: リポジトリの corpus/）")
    ap.add_argument("--tail", type=int, default=20000, help="各ログから読む末尾行数")
    ap.add_argument("--dry-run", action="store_true", help="書き込まず差分概要のみ表示")
    args = ap.parse_args()

    updates = build(args)
    if not updates:
        sys.stderr.write("更新対象なし。入力パス/接続を確認してください。\n")
        return 1

    out_dir = Path(args.out)
    for name, data in updates.items():
        if args.dry_run:
            n = 0
            if isinstance(data, dict):
                for k in ("ips", "iocs", "commands", "malicious_signatures", "malicious_paths"):
                    if isinstance(data.get(k), list):
                        n = len(data[k])
                        break
            print(f"[dry] {name}: ~{n} 件")
            continue
        (out_dir / name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"updated {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
