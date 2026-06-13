# Splunk 連携手順（はじめての方向け）

このシミュレータが生成した攻撃ログを Splunk に取り込むための手順書です。
**Splunk を触るのが初めて**でも進められるよう、まず「仕組み」をざっくり説明してから、
具体的な操作に入ります。

---

## 0. まず仕組みを理解する（5分）

### Splunk とは何をするものか
Splunk は **「あらゆるログを集めて、検索・可視化できる箱」** です。
ログを放り込むと全文検索エンジンが索引(インデックス)を作り、`index=... | stats ...` のような
独自言語(SPL)で集計・グラフ化できます。SOC では「攻撃ログを集めて分析する土台」になります。

### ログが Splunk に入るまで（3つのキーワード）
Splunk にログを送るとき、どのログにも次の3つのラベルが付きます。これだけ覚えれば十分です。

| ラベル | 意味 | 本ツールでの値（例) |
|---|---|---|
| **index** | ログの保存先（箱を分ける単位）。検索は `index=xxx` で始める | `tpot_sim` |
| **sourcetype** | ログの種類。フィールドの解釈方法を決める | `cowrie` / `suricata:eve` / `dionaea` / `tanner` |
| **source** | どこから来たか | `tpot-sim` |

> イメージ: **index = 引き出し**、**sourcetype = 書類の種類**、**source = 差出人**。
> 検索するときは「`tpot_sim` の引き出しから、`cowrie` という種類の書類を探す」という感覚です。

### どうやって送るか = HEC（HTTP Event Collector）
ログを Splunk に送る方法はいくつかありますが、本ツールは **HEC** を使います。

- HEC は Splunk が用意している **「ログ受付用の Web 窓口(HTTPのAPI)」** です。
- こちらは `https://<Splunk>:8088` に向けて、**トークン(合言葉)** を付けて JSON を POST するだけ。
- エージェントのインストール不要、ネットワーク的にも 8088 ポート1本で済むので、一番簡単です。

```
[ シミュレータ run.py ]  --HTTP POST(JSON + トークン)-->  [ Splunk :8088 HEC ]  -->  index=tpot_sim
```

これだけです。では実際に設定していきましょう。

---

## デプロイ前チェックリスト（Splunkサーバ＝環境B）

リポジトリ一式を Splunk サーバ(Linux)へ置いたら、まず以下を確認します。

```sh
# 1) Python 3.7 以上があるか（標準ライブラリのみ。pip不要）
python3 --version            # 3.7+ であること

# 2) 実行権限（git clone/scp で実行ビットが落ちることがある）
chmod +x simlog run.py tools/build_corpus.py
#   もし chmod できない/したくない場合は `sh simlog ...` で実行してもよい

# 3) コーパス同梱の確認（空でないこと）
ls corpus/                   # malicious_ips.json 等が並ぶ

# 4) 送信せず生成できるか（外部接続なしの最終確認）
python3 run.py --once --dry-run

# 5) Splunk の HEC ポートへ到達できるか（IP/ポートは自分の環境に合わせる）
curl -k https://<SplunkのIP>:8088/services/collector/health
#   {"text":"HEC is healthy"...} 等が返ればネットワークOK。
#   繋がらなければファイアウォールで 8088/tcp を許可
```

> **注意: `config.json` は純粋なJSON**です。手順書中の `//` で始まる注釈は説明用で、
> 実ファイルに書くと壊れます。編集するのは**値だけ**にしてください（コメントは `_note` キーで既に同梱）。

---

## 1. （任意だが推奨）専用インデックスを作る

検証ログを既存ログと混ぜないよう、専用の引き出し `tpot_sim` を作ります。

1. Splunk Web にログイン（通常 `http://<SplunkのIP>:8000`）
2. 上部メニュー **Settings（設定）→ Indexes（インデックス）**
3. 右上 **New Index**
4. **Index Name** に `tpot_sim` と入力 → 他はデフォルトのまま **Save**

> 作らない場合は、後の手順で index を `main`（既定の箱）にすればOKです。

---

## 2. HEC を有効化する

1. **Settings（設定）→ Data inputs（データ入力）**
2. 一覧から **HTTP Event Collector** をクリック
3. 右上 **Global Settings（全体設定）** を開く
   - **All Tokens** を **Enabled** にする
   - **Enable SSL**: チェックが入っていると `https`、外すと `http`。通常は**入れたまま(https)**でOK
   - **HTTP Port Number**: 既定 **8088**（このままでよい）
   - **Save**

> これで「HEC という受付窓口」が開きました。次に合言葉(トークン)を発行します。

---

## 3. HEC トークン（合言葉）を発行する

1. 同じ **HTTP Event Collector** 画面の右上 **New Token**
2. **Name**: `tpot-sim`（任意の名前）→ **Next**
3. **Input Settings** で:
   - **Source type**: `Automatic` のままでOK（送信側で種類を指定するため）
   - **Index**: 手順1で作った **`tpot_sim`** を選択（`Allowed Indexes` にも追加）
4. **Review → Submit**
5. 表示される **Token Value（`xxxxxxxx-xxxx-...` の文字列）をコピー** しておく

> このトークンが、シミュレータが Splunk に送るときの合言葉になります。**外部に漏らさない**こと。

---

## 4. シミュレータ側に設定する

**HECトークンは機密**なので `config.json` には書きません（コミットすると漏洩）。
代わりに **`config.local.json`**（gitignore済み・コミットされない）に置きます。

```sh
# テンプレートをコピーして実値を入れる
cp config.local.json.example config.local.json
```
`config.local.json` を編集（ここに書いた値が `config.json` を上書きします）:
```json
{
  "hec": {
    "url": "https://<SplunkのIP>:8088",
    "token": "<手順3でコピーした実トークン>",
    "index": "tpot_sim",
    "verify_tls": false
  }
}
```

> 別法: トークンだけ環境変数でも渡せます → `export SPLUNK_HEC_TOKEN=<トークン>`（最優先で適用）。
> `index` の既定や `eps`・`malicious_benign_ratio` 等、**機密でない設定は `config.json` を直接編集**してOK（追跡されます）。

> `verify_tls`: Splunk の HEC が自己署名のSSL証明書を使っている場合、`false` にしないと
> 証明書エラーで送れません。社内検証環境ではほぼ `false` でOKです。

> **sourcetype を自分のTA/アドオンに合わせたい場合**: `config.json` の `sourcetype_map` で変更できます。
> 例えば Suricata 用アドオンが `suricata` を期待するなら `"suricata:eve": "suricata"` に。
> （CTI製品やアプリが特定の sourcetype を前提にフィールド抽出する場合に効きます。
> 分からなければ既定のままでOK。後からの変更も可能です。）

---

## 5. 疎通テスト（1件だけ送ってみる）

シミュレータのある Linux サーバで:

```sh
./simlog test
```

これで **攻撃ログを1件だけ** HEC へ送ります。成功するとメッセージが出ます。
エラーが出た場合は[トラブルシューティング](#トラブルシューティング)へ。

### Splunk 側で着弾を確認
Splunk Web の **Search & Reporting（検索）** で、時間範囲を **Last 15 minutes** にして:

```spl
index=tpot_sim
```

イベントが1件出てくれば連携成功です 🎉

---

## 6. 連続供給を開始する

```sh
./simlog start     # バックグラウンドで連続供給を開始
./simlog status    # 動いているか確認
./simlog stop      # 止める
```

数分後、Splunk で件数が増えていきます。種類別に見るには:

```spl
index=tpot_sim | stats count by sourcetype
```

`cowrie` / `suricata:eve` / `dionaea` / `tanner` が並び、件数が増えていればOKです。

---

## 7. デモの流れ（このログで何を体験するか）

### ペインA: 「生ログだけだと意味が分からない」
```spl
index=tpot_sim sourcetype=cowrie | table _time src_ip username password input
```
→ `45.148.10.183` が攻撃者なのか、ただのスキャンなのか、**この時点では判断材料がない**。
これがアナリストの最初の痛みです。ここで **CTI 製品を連携**して `src_ip` をレピュテーション
照合すると、初めて「悪性/国/ISP/攻撃キャンペーン」の意味が付きます。

### ペインB: 「アラートが多すぎて疲れる」
```spl
index=tpot_sim | stats count by src_ip | sort -count
```
→ Censys / Shodan / ShadowServer といった **良性スキャナ**が大量に混ざっています。
これらは攻撃ではないのに件数を押し上げ、アラート疲れの原因になります。
**CTI 連携で「既知の良性スキャナ」を除外**すると、注視すべきアラートだけが残り、件数が激減します。

> この「Before（生ログ） → After（CTIエンリッチ/除外）」の対比こそが、本検証環境のゴールです。

---

## 便利な検索クエリ集

```spl
# 種類別の件数
index=tpot_sim | stats count by sourcetype

# SSH ブルートフォースの攻撃元 TOP10
index=tpot_sim sourcetype=cowrie eventid="cowrie.login.failed"
| stats count by src_ip | sort -count | head 10

# 狙われたユーザー名（暗号通貨ノード狙いが見える）
index=tpot_sim sourcetype=cowrie | top username

# Suricata の検知シグネチャ別
index=tpot_sim sourcetype=suricata:eve | stats count by alert.signature

# SMB スキャン(dionaea)の宛先ポート分布
index=tpot_sim sourcetype=dionaea | stats count by dst_port

# 時系列の流量（時間帯プロファイルの波が見える）
index=tpot_sim | timechart span=1m count
```

---

## トラブルシューティング

| 症状 | 原因 / 対処 |
|---|---|
| `HEC送信失敗` と出る | `url` のIP/ポート違い、または HEC 無効。手順2を再確認。`http`/`https` の取り違えも多い |
| 証明書エラー(SSL) | `config.json` の `"verify_tls": false` を確認（自己署名証明書のとき必須） |
| 401 / 403 が返る | トークンが違う / 失効。手順3でトークンを再確認・再発行 |
| 送信は成功するが検索に出ない | ① 検索の時間範囲が古い → **Last 15 minutes** に。② `index` 名がトークンの Allowed Indexes に無い → 手順3で追加 |
| `index=tpot_sim` で何も出ない | インデックス未作成。手順1で作るか、`config.json` の `index` を `main` に変更 |
| ポート 8088 に繋がらない | Splunkサーバのファイアウォールで 8088 を許可。`curl -k https://<Splunk>:8088/services/collector/health` で窓口の生死確認 |

### コマンドで直接 HEC を叩いて切り分け
シミュレータを介さず、HEC 単体が生きているか確認したいとき:

```sh
curl -k https://<SplunkのIP>:8088/services/collector/event \
  -H "Authorization: Splunk <トークン>" \
  -d '{"event":"hello from curl","sourcetype":"manual","index":"tpot_sim"}'
```
`{"text":"Success","code":0}` が返れば HEC とトークンは正常です（あとは送信側の設定問題に絞れます）。

---

## HEC が使えない場合（代替: ファイル取り込み）

会社のポリシーで HEC を開けない場合は、ファイル経由でも取り込めます。

1. `config.json` の `"output"` を `"file"` に変更
2. `./simlog start` → `out/` に `cowrie.json` / `eve.json` 等が JSON Lines で書き出される
3. Splunk の **Settings → Data inputs → Files & Directories** で `out/` を監視対象に追加
   （sourcetype は `cowrie` 等を手動指定）

仕組みは HEC と同じ（index / sourcetype を付けて取り込む）で、**入口がWebからファイルに変わるだけ**です。
```
