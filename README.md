# ClickFixGuard - ClickFix攻撃検知・防御ツール

## ClickFix攻撃とは？

Webサイトに偽のCAPTCHAやエラー画面を表示し、ユーザーに `Win+R → Ctrl+V → Enter` の操作を指示することで、クリップボードに仕込んだ悪意あるコマンドを実行させるソーシャルエンジニアリング攻撃です。

2024年から急増し、ESETの報告では2025年中頃までに検出数が**500%増加**。2026年も最も活発な初期アクセス手法の一つとされています。

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

## ビルド・実行

### 前提条件
- .NET 8 SDK

### ビルド
```bash
dotnet build -c Release
```

### 実行
```bash
dotnet run
# または
bin/Release/net8.0-windows/ClickFixGuard.exe
```

### スタートアップ登録（Windows起動時に自動実行）
1. `Win+R` → `shell:startup`
2. `ClickFixGuard.exe` のショートカットを配置

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `Program.cs` | エントリポイント（多重起動防止） |
| `TrayApplication.cs` | システムトレイ常駐、全コンポーネント統合 |
| `ClipboardMonitor.cs` | クリップボード定期監視 |
| `KeyboardHook.cs` | Win32低レベルキーボードフック |
| `ThreatPatterns.cs` | 危険パターン辞書（正規表現） |
| `WarningDialog.cs` | 警告ダイアログUI |

## 調査ソース

- [Microsoft Security Blog - ClickFix Analysis (2025/08)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [Microsoft Security Blog - CrashFix Variant (2026/02)](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)
- [Palo Alto Unit42 - Preventing ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [Sekoia - ClickFix Detection](https://blog.sekoia.io/clickfix-tactic-revenge-of-detection/)
- [Fortinet - Full PowerShell Attack Chain](https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain)
- [Krebs on Security - ClickFix](https://krebsonsecurity.com/2025/03/clickfix-how-to-infect-your-pc-in-three-easy-steps/)

## ライセンス

MIT
