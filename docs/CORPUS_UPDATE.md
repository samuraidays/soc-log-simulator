# 生ログ更新手順（コーパスの最新化）

T-POT の新しい生ログを取り込んで、シミュレータの「種」である `corpus/` を最新化する手順です。
**手動運用**を前提に、いつ・どこで・何をやるかを順番に書いています。

---

## 0. これは何をするのか（30秒で理解）

シミュレータは `corpus/*.json`（実データのスナップショット）を元に攻撃ログを生成します。
この種を、運用中 T-POT の**新しい生ログで入れ替える**のがコーパス更新です。

```
[T-POTの生ログ]  --build_corpus.py-->  [corpus/*.json を更新]  --コピー-->  [会社Splunkサーバで生成に使う]
   環境A（プライベート / T-POT接続可）                                    環境B
```

> ⚠️ これは「T-POT → Splunk 直結転送」ではありません。**種を更新するだけ**で、
> 会社サーバが T-POT に接続することはありません。

### どこから取るか（★重要: Wazuhからは取らない）
取得元は **T-POT VPS の「生ログ」**であって、Wazuh ではありません。

```
T-POT VPS (ssh tpot, port 64295)                         Wazuhサーバ (ssh wazuh, 別ホスト)
  honeypot → 生ログ ~/tpotce/data/<hp>/log/*.json
              │（enrichmentコンテナに /logs としてマウント）
              ▼
  enrichment_pipeline コンテナ
    /logs/... → エンリッチ → /output/honeypot_enriched.json ──送信──> wazuh-alerts-*
       ↑ ここ(生ログ=エンリッチ前)を取る                              （★エンリッチ後）
```

- **Wazuh の `wazuh-alerts-*` は abuse_score 等が付いたエンリッチ後**。ここからは取りません
  （取るとCTI製品にやらせるべき意味づけが最初から付いてしまう）。
- 本ツールは enrichment コンテナ内の `/logs/...`（パイプラインの**入力＝生ログ**）を
  `docker compose exec` で直接読みます。ホスト直下に `/logs` は無いためコンテナ経由です。
- `honeypot_enriched.json`（唯一のエンリッチ済みソース）は、次の**実データ**取得にだけ使います:
  - **良性/悪性のIP仕分け**（GreyNoise `gn_classification`）→ `benign_ips.json` / `malicious_ips.json`
  - **VT(GTI)確定済みの実マルウェアハッシュ**（`vt_malicious>0` のmd5 + `vt_family`）→ `malware_iocs.json`
  - これにより **GTI はハッシュ照会で実際に悪性判定でき、GreyNoise は良性スキャナを実際に除外できる**。
- 区別: dionaea の **md5 自体は生ログのデータ**（捕獲時にdionaeaが算出）なのでイベントに出力する。
  一方 **VT判定(vt_family/vt_malicious)はエンリッチなのでイベントには出さない**（GTIが付ける部分）。

### マルウェアIOC(sha256/URL/domain)は脅威フィード併用（ハイブリッド）
GTI 照会で確実に光らせたい sha256/URL/ドメインは、`tools/import_iocs.py` で abuse.ch
(ThreatFox/MalwareBazaar) の本物IOCを `corpus/malware_iocs.json` に**マージ取込**する。
`build_corpus.py`（T-POT由来）と `import_iocs.py`（フィード由来）は互いに上書きせず共存する。

```sh
python3 tools/import_iocs.py --source both --limit 40        # 要 abuse.ch Auth-Key（無料: https://auth.abuse.ch/）
python3 tools/import_iocs.py --from-file threatfox_dump.json # キーが無ければ手動DLのJSONから
```
> なぜ併用か: cowrie の `shasum` 等は本物だが「authorized_keys保存」などGTI未収録が多く不発になりやすい。
> abuse.ch は GTI が取り込む元ソースなのでヒットがほぼ確実。**ダミーは入れない**。
> Auth-Key は `config.local.json` の `feeds.abusech_auth_key` か環境変数 `ABUSECH_AUTH_KEY` に置く。

### いつやるか（更新の頻度）
鮮度が要るのは実質 **IOC（攻撃元IPの評判）だけ**です。目安はこれで十分:

| タイミング | やること |
|---|---|
| **四半期に1回** | 定期更新（`--dry-run` で差分を見てから本更新） |
| **大事なデモの直前** | 必ず1回。古いIPはCTIフィードから失効し相関が不発になるため |
| 月次ハントのついで | `--dry-run` で差分だけ眺め、変化が大きければ本更新 |

ダッシュボード練習・相関ルール検証・アラート疲れデモ等は**更新不要**（構造は古びない）。
→ 判断の詳細は [README](../README.md) や過去の検討メモ参照。

---

## 1. 前提（どこで実行するか）

- 実行するのは **環境A**＝プライベート側（`ssh tpot` できる端末。T-POT VPS は port 64295。
  Wazuhサーバ `wazuh` とは**別ホスト**）。
- **会社のSplunkサーバ（環境B）では実行しません。**
- 前提: T-POT 上で `enrichment_pipeline` コンテナが稼働していること
  （`ssh tpot "cd ~/tpotce && docker compose ps"` で確認）。ツールはこのコンテナの
  `/logs/...` を読みます。
- IOC（IP評判）まで更新したい場合は、同コンテナ内に `honeypot_enriched.json`
  （`/output/honeypot_enriched.json`）があること。無くてもコマンド/シグネチャ等は更新されます。

---

## 2. 更新する（2ステップ）

### ステップ1: まず差分を確認（書き込まない）
いきなり上書きせず、何がどれだけ変わるかを `--dry-run` で見ます。

```sh
cd /Users/takashi-h/Work/sim-honey-pot-log

# T-POT VPS へ SSH → enrichmentコンテナの生ログを読んで確認（書き込まない）
python3 tools/build_corpus.py --ssh-host tpot --dry-run
```

出力例:
```
[dry] cowrie_events.json: ~40 件
[dry] suricata_events.json: ~12 件
[dry] malicious_ips.json: ~55 件
[dry] benign_ips.json: ~22 件
```
件数がゼロや極端に少なければ、接続やパスを疑います（→ トラブルシューティング）。

### ステップ2: 問題なければ本更新（corpus/ を上書き）
```sh
python3 tools/build_corpus.py --ssh-host tpot
```
```
updated cowrie_events.json
updated suricata_events.json
updated malicious_ips.json
updated benign_ips.json
...
```
これで `corpus/*.json` が最新化されました。

> **生ログを手元に置いている場合**（SSHを使わない）:
> ```sh
> python3 tools/build_corpus.py --src-dir /path/to/logs
> ```
> `--src-dir` のフォルダに `cowrie.json` / `eve.json` / `dionaea.json` /
> `tanner_report.json`（任意で `honeypot_enriched.json`）を置いておきます。

---

## 3. 何が変わったか確認する

`git` を使っていれば差分が一目で分かります（このリポジトリを git 管理している場合）:
```sh
git diff --stat corpus/
git diff corpus/malicious_ips.json   # IOCの入れ替わりを確認
```

git を使っていなければ、生成サンプルで新しいIPが乗ったか確認:
```sh
python3 run.py --once --dry-run
# src_ip が新しいIOCに入れ替わっていればOK
```

---

## 4. 会社のSplunkサーバ（環境B）へ反映する

更新した `corpus/` を環境Bへ反映します。**git運用なら commit→push→pull が手軽**:

```sh
# 環境A: コミットして push
git add -A && git commit -m "refresh corpus/iocs" && git push

# 環境B（会社Splunkサーバ）: 取得して再起動
sudo git pull && sudo systemctl restart soc-log-simulator
#   systemd を使っていなければ: git pull && ./simlog restart
```

git を使わない場合は rsync/scp でも可:
```sh
rsync -av corpus/ <会社サーバ>:/opt/soc-log-simulator/corpus/
```

> 稼働中でなければ再起動は不要。次回起動から新コーパスが使われます。

---

## 5. うまくいったかの最終確認（環境B）

```sh
./simlog dry        # 新しいIP/コマンドが出るか目視
./simlog test       # HECへ1件 → Splunkで着弾確認
```
Splunk 側で、更新で入った新しい `src_ip` が出ていれば反映完了です。

---

## トラブルシューティング

| 症状 | 原因 / 対処 |
|---|---|
| `--dry-run` で全部0件 | ① ホスト違い: `tpot` を指定しているか（`wazuh` ではない）。② コンテナ未稼働: `ssh tpot "cd ~/tpotce && docker compose ps"` で `enrichment_pipeline` が Up か。③ 手動確認: `ssh tpot "cd ~/tpotce && docker compose exec -T enrichment_pipeline tail -n 3 /logs/cowrie/cowrie.json"` |
| サービス名/ディレクトリが違う | `--service <名前>` `--compose-dir <パス>` で上書き（既定: enrichment_pipeline / ~/tpotce） |
| `malicious_ips.json` だけ更新されない | コンテナ内に `/output/honeypot_enriched.json` が無い。IPの評判更新にはこれが必要（コマンド等は更新される） |
| SSH でパスワードを毎回聞かれる | `~/.ssh/config` に `tpot`(port 64295)の鍵認証を設定 |
| `docker compose` が無いと言われる | 旧形式なら `--service` はそのまま、ツール内の `docker compose` を環境に合わせる（要相談） |
| 取り込み件数を増やしたい | `--tail 50000` のように末尾行数を増やす（既定 20000） |
| 更新を取り消したい | git 管理なら `git checkout corpus/`。非git運用なら更新前にコピーを取っておく |

---

## まとめ早見表

```sh
# 環境A（T-POT VPS に ssh tpot できる側）で:
python3 tools/build_corpus.py --ssh-host tpot --dry-run     # 1. 差分確認
python3 tools/build_corpus.py --ssh-host tpot              # 2. 本更新（T-POTコンテキスト）
python3 tools/import_iocs.py --source both --limit 40      # 3. フィードから実IOC(sha256/URL/domain)
git add -A && git commit -m "refresh corpus/iocs" && git push   # 4. 反映（git運用）

# 環境B（会社Splunkサーバ）で:
sudo git pull && sudo systemctl restart soc-log-simulator  # 5. 取得して再起動
#   （systemdでなければ git pull 後 ./simlog restart）
```

頻度は **四半期に1回＋大事なデモの前** で十分です。
