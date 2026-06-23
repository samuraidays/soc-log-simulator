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

## 共有サーバでの運用（Splunkを触る全員が起動/停止）

「誰でも起動/停止できる」ようにするなら、**`/opt` に置いて systemd サービス**にするのが定石。
`./simlog start` 方式は手軽だが、起動した本人以外がプロセスを止められない（UIDが違うと `kill` 不可）
という多人数の壁があるため、共有環境では systemd を推奨。

### 1. 設置（一度だけ・管理者）
```sh
# /opt に配置（誰かのホームに置かない）
sudo git clone https://github.com/samuraidays/soc-log-simulator.git /opt/soc-log-simulator
cd /opt/soc-log-simulator
sudo chmod +x simlog run.py tools/build_corpus.py

# 実トークンを設定（このファイルは追跡されない。所有者と権限を絞る）
sudo cp config.local.json.example config.local.json
sudo vi config.local.json
sudo chown splunk:splunk config.local.json && sudo chmod 640 config.local.json

# サービス登録
sudo cp simlog.service /etc/systemd/system/soc-log-simulator.service
sudo systemctl daemon-reload
sudo systemctl enable --now soc-log-simulator
```

### 2. 全員が操作できるようにする（sudoers で対象サービスだけ許可）
個人アカウントのまま、このサービスの start/stop だけを許可する（root全権は渡さない）:
```sh
# 操作を許可するグループを用意（例: soc）し、Splunk担当者を追加
sudo groupadd -f soc && sudo usermod -aG soc <ユーザー名>

# /etc/sudoers.d/soc-log-simulator として保存（visudo推奨）
%soc ALL=(root) NOPASSWD: /usr/bin/systemctl start soc-log-simulator, \
  /usr/bin/systemctl stop soc-log-simulator, \
  /usr/bin/systemctl restart soc-log-simulator, \
  /usr/bin/systemctl status soc-log-simulator
```

### 3. 各自の操作（誰でも・どの順でも）
```sh
sudo systemctl start  soc-log-simulator   # 開始
sudo systemctl stop   soc-log-simulator   # 停止
sudo systemctl status soc-log-simulator   # 稼働確認
journalctl -u soc-log-simulator -f        # ログ追尾（送信件数/エラー）
```
誰が起動しても誰でも停止でき、サーバ再起動後も自動起動、異常時は自動再起動（`Restart=on-failure`）。

### 設定変更（EPS や悪性:良性比）
`/opt/soc-log-simulator/config.json` を編集 → `sudo systemctl restart soc-log-simulator`。

> **より簡単な代替**: 担当者が全員 `splunk` など**共有アカウントで作業**する運用なら、systemd を使わず
> `/opt/soc-log-simulator` を `splunk` 所有にして `./simlog start|stop` でも回せる
> （同一ユーザーなので停止権限の問題が出ない）。個人アカウント運用なら上の systemd 方式が安全。

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
- **dionaea**: `connection.protocol`, `dst_port`(445等), `download.md5_hash`/`sha256_hash`/`url`/`host`
- **tanner**: `peer.ip`, `path`(.env/.aws等), `method`, `headers.user-agent`
- **cowrie**(一部): `input` に本物のマルウェアURLを使った `wget` コマンド（URL/ドメインIOC）

### 本物のマルウェアIOC（sha256 / ドメイン / URL）を GTI でエンリッチする
GTI(VirusTotal)が照会して悪性判定する**実IOC**を `corpus/malware_iocs.json` に置く。
dionaea(検体DL)と cowrie(wget) がここから引いて出力する。day-one は EICAR(実ハッシュ/全AV必中)入り。

**ハイブリッド方式（推奨）**: 攻撃の外側(IP/コマンド/キャンペーン)はT-POT実データ、
埋め込むペイロードIOC(sha256/URL/domain)はGTI確実ヒットの脅威フィードから供給する。
2つのツールが `malware_iocs.json` に**マージ**で書き込む（互いに上書きしない・重複排除）:

```sh
# ① 脅威フィードから GTI確実ヒットの実IOC（sha256/URL/domain）を取得
#    abuse.ch の無料Auth-Key が必要（https://auth.abuse.ch/）。config.local.json の feeds か環境変数で渡す
python3 tools/import_iocs.py --source both --limit 40
#    キーがまだ無ければ、手動DLしたJSONからでも取り込める（キー不要）
python3 tools/import_iocs.py --from-file threatfox_dump.json

# ② 自分のT-POTの実観測（VT確定検体md5、cowrieのwget URL 等）も取り込む
python3 tools/build_corpus.py --ssh-host tpot
```

> **なぜフィード併用か**: cowrieの `shasum` 等は本物だが「authorized_keys保存」など**GTI未収録**が多く、
> エンリッチが不発になりやすい。abuse.ch(MalwareBazaar=sha256+family / URLhaus・ThreatFox=URL+domain)は
> **GTIが取り込む元ソース**なので、Splunkでのエンリッチがほぼ確実に当たる。**ダミーは入れない**。

#### Splunk 側の GTI エンリッチ
GTI/VirusTotal の Splunk アプリ（または GTI連携）で、生成ログの `sha256_hash` / `download.url` /
ドメイン等のフィールドを照会 → 悪性判定・マルウェアファミリ・関連ドメインを付与。
生ログ単体では意味不明（ペインA）→ GTIエンリッチで意味が付く、という流れを体感できる。

`abuse_score` や `gn_classification` 等のエンリッチ値は**あえて含めない**（CTI 製品が付与する部分）。

## 留意点
- `corpus/` には実 IP・実コマンドが含まれる。社内検証用途として持ち込む範囲は要判断。
- HEC が使えない場合は `config.json` の `"output": "file"` にすると JSON Lines を
  `out/` に出力し、Splunk forwarder / file monitor で取り込める。
