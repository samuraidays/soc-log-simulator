# sim-honey-pot-log — T-POT 攻撃ログ・シミュレータ → Splunk

ハニーポットを**運用せずに**、実観測データ(IOC/コマンド/シグネチャ)に基づく
**生の攻撃ログ＋良性ノイズ**を Splunk に常時供給するツール。
CTI(脅威インテリジェンス)製品連携の SOC 検証環境向け。

## このツールが解決すること

会社でハニーポットを運用するのはリスクが高い。一方、SOC/CTI 検証には継続的な攻撃ログが要る。
本ツールは、プライベートの `code-wazuh-threat-hunting`(T-POT + Wazuh) で蓄積した実データを
コーパス化し、それを元に現実的な攻撃ログを生成して Splunk HEC へ流し込む。**攻撃は一切実行しない。**

### デモのねらい: 「ペイン体験 → CTI で解決」
- **ペインA（生ログは意味不明）**: 素の cowrie/suricata ログを見ても `45.148.10.183` が悪いか分からない
  → CTI 製品を連携してエンリッチ → レピュテーション/分類/ジオが付き**意味が生まれる**。
- **ペインB（アラート疲れ）**: 良性スキャナ(Censys/Shodan/ShadowServer 等)が大量に混ざりアラートが膨れる
  → CTI で既知良性を除外 → **アラートが減る**。

→ そのため本ツールの出力は**エンリッチ前の生ログ**であり、良性ノイズを意図的に多めに混ぜている
(`malicious_benign_ratio`)。エンリッチは CTI 製品の仕事。

## 構成と前提

- **言語**: Python 3（**標準ライブラリのみ・pip 不要**）。Linux の Splunk サーバでそのまま動く。
- **唯一の事前作業**: Splunk 側で HEC を有効化しトークンを発行（下記）。

```
corpus/        実データ由来シード（同梱済み。すぐ動く）
generator/     生ログ生成エンジン（source別: cowrie/dionaea/suricata/tanner）
tools/         build_corpus.py（T-POT生ログから corpus を再生成。環境A用）
config.json    設定（ここだけ編集すればよい）
run.py         本体
simlog         start/stop/status/test ラッパー
```

## セットアップ（会社の Splunk サーバ = 環境B）

> **Splunk が初めての方へ:** 仕組みの説明から画面操作・確認クエリ・トラブル対処まで
> 丁寧にまとめた **[docs/SPLUNK_SETUP.md](docs/SPLUNK_SETUP.md)** を先に読むのがおすすめです。
> 以下はその要約です。

### 1. Splunk で HEC トークンを発行
Splunk Web → **Settings → Data inputs → HTTP Event Collector**
1. **Global Settings** で *All Tokens = Enabled*（必要なら SSL 設定を確認、既定ポート 8088）
2. **New Token** を作成。任意で専用インデックス(例 `tpot_sim`)を作って割り当て
3. 発行された**トークン文字列**をコピー

### 2. config.json を編集
```jsonc
"hec": {
  "url": "https://<splunkのIP>:8088",
  "token": "<発行したトークン>",
  "index": "tpot_sim",
  "verify_tls": false   // 自己署名証明書ならfalse
}
```
良性ノイズの比率やレートも調整可:
- `"eps": 5` … 平均イベント/秒（時間帯で自動増減）
- `"malicious_benign_ratio": [1, 4]` … 悪性:良性。良性多めでアラート疲れを再現

### 3. 疎通確認 → 連続供給
```sh
./simlog test      # HECへ1件送信。Splunkで index=tpot_sim を検索して着弾確認
./simlog start     # 連続供給を開始（バックグラウンド）
./simlog status    # 稼働状況
./simlog stop      # 停止
```
送信せず形だけ見たいとき:
```sh
./simlog dry       # 標準出力に生ログサンプルを表示（送信なし）
```

### 常駐させる場合（任意）
`simlog.service` のパスを実配置に合わせて編集し:
```sh
sudo cp simlog.service /etc/systemd/system/
sudo systemctl enable --now simlog
```

## 配布とデプロイ（GitHub等）

Splunkサーバへ持っていく方法。**GitHubで配るなら必ず Private リポジトリ**にすること
（実攻撃IP・社内ホスト名 `tpot`/`wazuh` 等を含むため）。

**機密の扱い（重要）:** HECトークンは**コミットしない**。
`config.json` はテンプレート（プレースホルダ）のまま追跡し、実トークンは
`config.local.json`（`.gitignore`済み）か環境変数 `SPLUNK_HEC_TOKEN` に置く。
`.gitignore` で `*.local.json` / `.claude/` / `.env` を除外済み。

```sh
# 配布側（一度だけ）
git init && git add . && git commit -m "init"
git remote add origin git@github.com:<you>/sim-honey-pot-log.git   # ← Privateで作成
git push -u origin main

# Splunkサーバ側
git clone git@github.com:<you>/sim-honey-pot-log.git
cd sim-honey-pot-log
chmod +x simlog run.py tools/build_corpus.py
cp config.local.json.example config.local.json   # ここに実トークンを記入（コミットされない）
./simlog test
```

更新は Splunkサーバで `git pull` だけ。**コーパス更新（環境A）と相性が良い**:
環境Aで `corpus/` を再生成→commit→push、Splunkサーバで `git pull && ./simlog restart`。

### もっと簡単な方法（GitHub無しでもよい場合）
1台のSplunkサーバに置くだけなら、GitHubを介さず直接コピーでも十分:
```sh
# tar で固めて転送（.git や local 設定を除外）
tar --exclude='.git' --exclude='*.local.json' --exclude='__pycache__' \
    -czf sim.tgz . && scp sim.tgz <splunk>:/opt/ && ssh <splunk> 'cd /opt && tar xzf sim.tgz'

# または rsync（コーパスだけの再同期にも使える）
rsync -av --exclude='.git' --exclude='*.local.json' ./ <splunk>:/opt/sim-honey-pot-log/
```
**使い分け**: 複数人で使う/更新を `git pull` で回したい → **Git(Private)**。
1台に置いて時々 `corpus/` を rsync するだけ → **tar/rsync** が手軽。どちらも機密は同梱されない。

## Splunk 側の確認クエリ例
```spl
index=tpot_sim                       | stats count by sourcetype
index=tpot_sim sourcetype=cowrie     | stats count by src_ip username
index=tpot_sim sourcetype=suricata:eve | stats count by alert.signature
```
CTI 連携後は、`src_ip` をレピュテーション lookup で突き合わせ、
良性スキャナ(Censys/Shodan/ShadowServer)を除外するとアラートが減ることを体感できる。

## コーパスの更新（環境A = T-POT/Wazuh にアクセスできる側）

> 手順の詳細・確認方法・更新頻度の目安は **[docs/CORPUS_UPDATE.md](docs/CORPUS_UPDATE.md)** にまとめてあります。

会社サーバはコーパス同梱で即動くが、実データを最新化したいときは**プライベート側**で実行:
```sh
# T-POT VPS の enrichment コンテナの生ログ(エンリッチ前)を読んで corpus/ を再生成
# 取得元は Wazuh(=エンリッチ後)ではなく、その手前の /logs/... 生ログ
python3 tools/build_corpus.py --ssh-host tpot --dry-run   # まず差分確認
python3 tools/build_corpus.py --ssh-host tpot             # 本更新

# もしくは生ログをローカルに置いて
python3 tools/build_corpus.py --src-dir /path/to/logs
```
更新された `corpus/*.json` を会社サーバへコピーすれば反映完了
（シミュレータ実行時に T-POT/Wazuh へ接続することは一切ない）。

## 出力フォーマット（生ログ＝エンリッチ前）
- **cowrie**: `eventid`(login.failed/success, command.input, session.connect), `src_ip`,`username`,`password`,`input`,`session`
- **suricata**: EVE `event_type:alert`, `src_ip`/`dest_ip`, `alert.signature/category/severity`
- **dionaea**: `connection.protocol`, `dst_port`(445等), `download.md5_hash`/`url`
- **tanner**: `peer.ip`, `path`(.env/.aws等), `method`, `headers.user-agent`

`abuse_score` や `gn_classification` 等のエンリッチ値は**あえて含めない**（CTI 製品が付与する部分）。

## 留意点
- `corpus/` には実 IP・実コマンドが含まれる。社内検証用途として持ち込む範囲は要判断。
- HEC が使えない場合は `config.json` の `"output": "file"` にすると JSON Lines を
  `out/` に出力し、Splunk forwarder / file monitor で取り込める。
