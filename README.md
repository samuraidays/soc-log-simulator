# soc-log-simulator — T-POT 攻撃ログ・シミュレータ → Splunk

ハニーポットを**運用せずに**、実観測データ(IOC/コマンド/シグネチャ)に基づく
**生の攻撃ログ＋良性ノイズ**を Splunk に常時供給するツール。
CTI(脅威インテリジェンス)製品連携の SOC 検証環境向け。**攻撃は一切実行しない。**

GitHub: `samuraidays/soc-log-simulator`（Private）

## このツールが解決すること

会社でハニーポットを運用するのはリスクが高い。一方、SOC/CTI 検証には継続的な攻撃ログが要る。
本ツールは、プライベートの `code-wazuh-threat-hunting`(T-POT + Wazuh) で蓄積した実データを
コーパス化し、それを元に現実的な攻撃ログを生成して Splunk HEC へ流し込む。

### デモのねらい: 「ペイン体験 → CTI で解決」
- **ペインA（生ログは意味不明）**: 素の cowrie/suricata ログや `sha256`/IP を見ても悪性か分からない
  → CTI(GTI等)を連携してエンリッチ → レピュテーション/マルウェアファミリ/分類が付き**意味が生まれる**。
- **ペインB（アラート疲れ）**: 良性スキャナ(Censys/Shodan/ShadowServer 等)が大量に混ざりアラートが膨れる
  → CTI で既知良性を除外 → **アラートが減る**。

→ そのため出力は**エンリッチ前の生ログ**で、良性ノイズを意図的に多めに混ぜている
(`malicious_benign_ratio`)。`abuse_score`/`gn_classification` 等のエンリッチ値は**あえて含めない**
（CTI 製品が付与する部分）。

## 構成

Python 3.7+（**標準ライブラリのみ・pip 不要**）。Linux の Splunk サーバでそのまま動く。

```
corpus/        実データ由来シード（同梱済み・すぐ動く）
               malicious_ips / benign_ips / cowrie / dionaea / suricata / tanner /
               malware_iocs(sha256/URL/domain) / timeline_profile
generator/     生ログ生成エンジン（sources: cowrie/dionaea/suricata/tanner, outputs: hec/file）
tools/         build_corpus.py（T-POT生ログ→corpus再生成） / import_iocs.py（脅威フィード→実IOC取込）
config.json            設定テンプレート（機密は入れない）
config.local.json      実トークン等（.gitignore済み・各環境で作成）
run.py / simlog / simlog.service   本体・起動ラッパー・systemdユニット
docs/          SPLUNK_SETUP.md（Splunk連携手順） / CORPUS_UPDATE.md（実データ更新）
```

## クイックスタート（Splunk サーバ = 環境B）

> Splunk が初めてなら、画面操作・確認クエリ・トラブル対処まで丁寧にまとめた
> **[docs/SPLUNK_SETUP.md](docs/SPLUNK_SETUP.md)** を参照。以下は要約。

1. **HEC トークン発行**: Splunk Web → Settings → Data inputs → HTTP Event Collector
   → Global Settings で *All Tokens = Enabled*（既定ポート 8088）→ New Token 作成（専用index `tpot_sim` 推奨）
2. **トークンを設定（config.json には書かない）**:
   ```sh
   cp config.local.json.example config.local.json   # ここに url/token/index を記入（コミットされない）
   # 別法: export SPLUNK_HEC_TOKEN=<トークン>（最優先で適用）
   ```
3. **疎通 → 連続供給**:
   ```sh
   ./simlog test     # HECへ1件 → Splunkで index=tpot_sim を検索して着弾確認
   ./simlog start    # 連続供給（バックグラウンド）
   ./simlog status   # 稼働確認
   ./simlog stop     # 停止
   ./simlog dry      # 送信せず生ログ形式を標準出力（確認用）
   ```

### よく使う設定（`config.json`）
- `"eps": 5` … 平均イベント/秒（時間帯で自動増減）
- `"malicious_benign_ratio": [1, 4]` … 悪性:良性。良性多めでアラート疲れを再現
- `"sourcetype_map"` … 送信時の sourcetype を Splunk の TA に合わせて変更可（例 `suricata:eve`→`suricata`）
- `"output": "file"` … HEC が使えない場合は JSON Lines を `out/` に出力（forwarder/monitor で取込）

## デプロイ

### 機密の扱い（最初に確認）
HEC トークンは**コミットしない**。`config.json` はテンプレートのまま追跡し、実値は
`config.local.json`（`.gitignore`済み）か環境変数 `SPLUNK_HEC_TOKEN` に置く。
`.gitignore` で `*.local.json` / `.claude/` / `.env` を除外済み。
**GitHub で配るなら必ず Private**（実攻撃IP・社内ホスト名を含むため）。

### A. 共有サーバで全員が起動/停止（複数人・推奨）
`/opt` に置いて systemd サービスにする。`./simlog start` 方式は起動者以外が止められない
（UID が違うと `kill` 不可）ため、共有環境では systemd が安全。

```sh
# 設置（管理者・一度だけ）
sudo git clone https://github.com/samuraidays/soc-log-simulator.git /opt/soc-log-simulator
cd /opt/soc-log-simulator
sudo chmod +x simlog run.py tools/*.py
sudo cp config.local.json.example config.local.json && sudo vi config.local.json   # 実トークン記入
sudo chown splunk:splunk config.local.json && sudo chmod 640 config.local.json
sudo cp simlog.service /etc/systemd/system/soc-log-simulator.service
sudo systemctl daemon-reload && sudo systemctl enable --now soc-log-simulator

# 全員に start/stop だけ許可（root全権は渡さない）。/etc/sudoers.d/soc-log-simulator に:
#   %soc ALL=(root) NOPASSWD: /usr/bin/systemctl start soc-log-simulator, \
#     /usr/bin/systemctl stop soc-log-simulator, /usr/bin/systemctl restart soc-log-simulator, \
#     /usr/bin/systemctl status soc-log-simulator
sudo groupadd -f soc && sudo usermod -aG soc <ユーザー名>
```
各自の操作:
```sh
sudo systemctl start|stop|status soc-log-simulator
journalctl -u soc-log-simulator -f      # 送信件数/エラーの追尾
```
設定変更は `config.json` 編集 → `sudo systemctl restart soc-log-simulator`。
誰が起動しても誰でも停止でき、再起動後も自動起動・異常時は自動再起動。

### B. 単体サーバで手軽に
```sh
git clone https://github.com/samuraidays/soc-log-simulator.git && cd soc-log-simulator
chmod +x simlog run.py tools/*.py
cp config.local.json.example config.local.json   # 実トークン記入
./simlog test && ./simlog start
```
GitHub を使わないなら tar/rsync でも可（機密は同梱されない）:
```sh
rsync -av --exclude='.git' --exclude='*.local.json' ./ <splunk>:/opt/soc-log-simulator/
```

## コーパス / IOC の更新（環境A = T-POT にアクセスできる側）

> 詳細・頻度の目安・トラブル対処は **[docs/CORPUS_UPDATE.md](docs/CORPUS_UPDATE.md)**。

会社サーバは同梱コーパスで即動く。実データを最新化したいときだけ**プライベート側**で実行し、
更新した `corpus/` を会社サーバへ反映（`git pull && sudo systemctl restart soc-log-simulator`）。

```sh
# ① T-POT の生ログ(エンリッチ前)から攻撃コンテキストを再生成
#    取得元は Wazuh(=エンリッチ後)ではなく、enrichment コンテナ内の /logs 生ログ
python3 tools/build_corpus.py --ssh-host tpot --dry-run   # まず差分確認
python3 tools/build_corpus.py --ssh-host tpot             # 本更新

# ② 脅威フィードから GTI確実ヒットの実IOC(sha256/URL/domain)を取込（ハイブリッド）
python3 tools/import_iocs.py --source both --limit 40     # 要 abuse.ch Auth-Key
python3 tools/import_iocs.py --from-file threatfox_dump.json   # キーが無ければ手動DLのJSONから
```
両ツールは `corpus/malware_iocs.json` に**マージ**で書き込む（互いに上書きしない・重複排除）。

## 出力フォーマット（生ログ＝エンリッチ前）
- **cowrie**: `eventid`(login.failed/success, command.input, session.connect), `src_ip`,`username`,`password`,`input`,`session`
  — `input` の一部に本物のマルウェアURLを使った `wget` コマンド（URL/ドメインIOC）
- **dionaea**: `connection.protocol`, `dst_port`(445等), `download.md5_hash`/`sha256_hash`/`url`/`host`
- **suricata**: EVE `event_type:alert`, `src_ip`/`dest_ip`, `alert.signature/category/severity`
- **tanner**: `peer.ip`, `path`(.env/.aws等), `method`, `headers.user-agent`

### GTI でのエンリッチ（Splunk 側）
`corpus/malware_iocs.json` の実IOC（GTI が照会して悪性判定するもの）を dionaea/cowrie が出力する。
day-one は EICAR(実ハッシュ・全AV必中)入り。**ハイブリッド方式**で、攻撃の外側(IP/コマンド)は T-POT 実データ、
埋め込む sha256/URL/domain は GTI 確実ヒットの脅威フィード(abuse.ch ThreatFox/MalwareBazaar)から供給する。
Splunk 側は GTI/VirusTotal アプリで `sha256_hash`/`download.url`/ドメイン等を照会 → ファミリ・悪性判定を付与。
> cowrie の `shasum` 等は本物だが GTI 未収録が多くエンリッチ不発になりやすいため、IOC はフィード併用が確実。**ダミーは入れない**。

## Splunk 確認クエリ例
```spl
index=tpot_sim | stats count by sourcetype
index=tpot_sim sourcetype=cowrie | stats count by src_ip username
index=tpot_sim sourcetype=suricata:eve | stats count by alert.signature
index=tpot_sim sourcetype=dionaea download.sha256_hash=* | table _time src_ip download.sha256_hash download.url
```

## 留意点
- `corpus/` には実 IP・実コマンド・実IOC が含まれる。持ち込む範囲は社内ポリシーで要判断。
- 実行時に T-POT/Wazuh へ接続することは一切ない（コーパス更新は環境Aで別途行う）。
