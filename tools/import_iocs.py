#!/usr/bin/env python3
"""import_iocs — GTIでエンリッチ可能な本物のIOC(sha256/URL/domain)を脅威フィードから取込む。

abuse.ch の ThreatFox / MalwareBazaar から実IOCを取得し corpus/malware_iocs.json に
マージする。これらは GTI/VirusTotal が取り込んでいる元ソースなので、Splunk での GTI
エンリッチがほぼ確実に当たる（=デモのクライマックスが不発にならない）。

Auth-Key（無料）: https://auth.abuse.ch/ でアカウント作成し発行。
  環境変数 ABUSECH_AUTH_KEY か config.local.json の feeds.abusech_auth_key に設定。

使い方:
  python3 tools/import_iocs.py --source both --limit 30        # APIから取得（要Auth-Key）
  python3 tools/import_iocs.py --from-file threatfox_dump.json # 手動DLしたJSONから（キー不要）
  python3 tools/import_iocs.py --source threatfox --dry-run    # 取得して表示のみ
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
CTX = ssl.create_default_context()

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


def get_auth_key(args) -> str | None:
    if args.auth_key:
        return args.auth_key
    if os.environ.get("ABUSECH_AUTH_KEY"):
        return os.environ["ABUSECH_AUTH_KEY"]
    local = ROOT / "config.local.json"
    if local.exists():
        try:
            return (json.loads(local.read_text()).get("feeds", {}) or {}).get("abusech_auth_key")
        except Exception:  # noqa: BLE001
            pass
    return None


def host_from_url(s: str) -> str:
    if "://" in s:
        s = s.split("://", 1)[1]
    return s.split("/", 1)[0].split(":", 1)[0]


def _post(url: str, payload: dict, key: str | None, form: bool = False) -> dict:
    headers = {}
    if key:
        headers["Auth-Key"] = key
    if form:
        data = urllib.parse.urlencode(payload).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _rows(resp: dict) -> list:
    """abuse.ch レスポンスの data を list で返す（dict形式のダンプにも対応）。"""
    data = resp.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        out = []
        for v in data.values():
            out.extend(v if isinstance(v, list) else [v])
        return out
    return []


def parse_threatfox(rows: list) -> list[dict]:
    """ThreatFox の混在IOC(url/domain/sha256/md5)を共通形式へ。"""
    iocs = []
    for d in rows:
        t = d.get("ioc_type", "")
        val = d.get("ioc", "")
        fam = d.get("malware_printable") or d.get("malware", "")
        if not val:
            continue
        if t == "url":
            iocs.append({"url": val, "domain": host_from_url(val), "vt_family": fam})
        elif t in ("domain", "hostname"):
            iocs.append({"domain": val, "vt_family": fam})
        elif t == "sha256_hash":
            iocs.append({"sha256": val, "vt_family": fam})
        elif t == "md5_hash":
            iocs.append({"md5": val, "vt_family": fam})
    return iocs


def parse_malwarebazaar(rows: list) -> list[dict]:
    iocs = []
    for d in rows:
        sha = d.get("sha256_hash", "")
        md5 = d.get("md5_hash", "")
        if not (sha or md5):
            continue
        iocs.append({"sha256": sha, "md5": md5,
                     "filename": d.get("file_name", ""),
                     "vt_family": d.get("signature") or d.get("file_type", "")})
    return iocs


def fetch(args, key: str | None) -> list[dict]:
    if args.from_file:
        resp = json.loads(Path(args.from_file).read_text())
        rows = _rows(resp)
        # ダンプ種別を中身から推定
        if rows and "ioc_type" in rows[0]:
            return parse_threatfox(rows)
        return parse_malwarebazaar(rows)

    if not key:
        sys.stderr.write(
            "Auth-Key がありません。https://auth.abuse.ch/ で無料発行し、\n"
            "  export ABUSECH_AUTH_KEY=... または config.local.json の feeds.abusech_auth_key に設定。\n"
            "  あるいは --from-file で手動DLしたJSONを読み込んでください。\n")
        return []

    iocs: list[dict] = []
    if args.source in ("threatfox", "both"):
        r = _post(THREATFOX_API, {"query": "get_iocs", "days": args.days}, key)
        if r.get("query_status") == "ok":
            iocs += parse_threatfox(_rows(r))
        else:
            sys.stderr.write(f"[warn] ThreatFox: {r.get('query_status')}\n")
    if args.source in ("malwarebazaar", "both"):
        r = _post(MALWAREBAZAAR_API, {"query": "get_recent", "selector": "time"}, key, form=True)
        if r.get("query_status") == "ok":
            iocs += parse_malwarebazaar(_rows(r))
        else:
            sys.stderr.write(f"[warn] MalwareBazaar: {r.get('query_status')}\n")
    return iocs


def ioc_key(i: dict) -> str:
    return i.get("sha256") or i.get("md5") or i.get("url") or i.get("domain") or ""


def merge_into_corpus(new_iocs: list[dict], limit: int, dry: bool) -> int:
    path = CORPUS / "malware_iocs.json"
    doc = json.loads(path.read_text())
    existing = doc.get("iocs", [])
    orig_count = len(existing)
    seen = {ioc_key(i) for i in existing if ioc_key(i)}
    # ハッシュ型(sha256/md5)を優先。ドメイン/URL型はThreatFoxで件数が多く、
    # 優先しないと limit 内をドメイン/URL型だけで食い尽くしハッシュ型が0件になりうる。
    ordered = sorted(new_iocs, key=lambda i: 0 if (i.get("sha256") or i.get("md5")) else 1)
    added = 0
    for i in ordered:
        k = ioc_key(i)
        if not k or k in seen:
            continue
        seen.add(k)
        existing.append({kk: vv for kk, vv in i.items() if vv})
        added += 1
        if added >= limit:
            break
    if dry:
        for i in ordered[:limit]:
            print("  ", {k: v for k, v in i.items() if v})
        print(f"[dry] 追加候補 {min(added, limit)} 件（既存 {orig_count} 件にマージ）")
        return added
    doc["iocs"] = existing
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return added


def main() -> int:
    ap = argparse.ArgumentParser(description="脅威フィード(abuse.ch)から実IOCを取り込む")
    ap.add_argument("--source", choices=["threatfox", "malwarebazaar", "both"], default="both")
    ap.add_argument("--from-file", help="手動DLしたabuse.chのJSONダンプから読む（キー不要）")
    ap.add_argument("--auth-key", help="abuse.ch Auth-Key（未指定なら環境変数/config.local.json）")
    ap.add_argument("--days", type=int, default=3, help="ThreatFoxで遡る日数")
    ap.add_argument("--limit", type=int, default=40, help="追加する最大IOC数")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    key = get_auth_key(args)
    iocs = fetch(args, key)
    if not iocs:
        sys.stderr.write("取得IOCなし。\n")
        return 1
    added = merge_into_corpus(iocs, args.limit, args.dry_run)
    if not args.dry_run:
        print(f"malware_iocs.json に {added} 件追加")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
