using System.Text.RegularExpressions;

namespace ClickFixGuard;

/// <summary>
/// ClickFix攻撃で使われる危険なクリップボードパターンを検知するエンジン。
/// 調査に基づく実際の攻撃パターンを網羅。
/// </summary>
public static class ThreatPatterns
{
    /// <summary>検知結果</summary>
    public record ThreatMatch(ThreatLevel Level, string Category, string Description, string MatchedFragment);

    public enum ThreatLevel
    {
        Safe,       // 安全
        Suspicious, // 要注意（黄色警告）
        Critical    // 危険（赤警告・ブロック）
    }

    // === 危険度: Critical（ほぼ確実に攻撃） ===
    private static readonly (Regex Pattern, string Category, string Description)[] CriticalPatterns =
    [
        // PowerShell ダウンロード＆実行（ClickFixの最も一般的なパターン）
        (new Regex(@"powershell.*Invoke-Expression", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell IEX", "PowerShellでリモートコードを実行しようとしています"),

        (new Regex(@"powershell.*IEX\s*\(", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell IEX", "PowerShellでリモートコードを実行しようとしています"),

        (new Regex(@"powershell.*Invoke-WebRequest", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Download", "PowerShellで外部からファイルをダウンロードしようとしています"),

        (new Regex(@"powershell.*Invoke-RestMethod", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Download", "PowerShellでREST APIから悪意あるコードを取得しようとしています"),

        (new Regex(@"powershell.*\bIWR\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell IWR", "PowerShellでファイルダウンロードのショートカットが使われています"),

        (new Regex(@"powershell.*DownloadString", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Download", "PowerShellでリモートスクリプトをダウンロードしようとしています"),

        (new Regex(@"powershell.*DownloadFile", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Download", "PowerShellでファイルをダウンロードしようとしています"),

        (new Regex(@"powershell.*Start-Process", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Exec", "PowerShellで別のプログラムを起動しようとしています"),

        // Base64エンコード実行（隠蔽の典型）
        (new Regex(@"powershell.*-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Encoded", "Base64エンコードされた隠しコマンドを実行しようとしています"),

        // WindowStyle Hidden（ユーザーから隠す）
        (new Regex(@"-W(indowStyle)?\s+Hidden", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Hidden Execution", "ウィンドウを隠してコマンドを実行しようとしています"),

        // mshta（ClickFix Phantom Meetパターン）
        (new Regex(@"mshta\s+https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "MSHTA Remote", "mshta.exeでリモートのHTMLアプリケーションを実行しようとしています"),

        (new Regex(@"mshta\s+\S+\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "MSHTA Obfuscated", "mshta.exeで難読化されたコマンドを実行しようとしています"),

        // bitsadmin（ClickFix Phantom Meetの第2段階）
        (new Regex(@"bitsadmin.*/(transfer|download)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "BITSAdmin Download", "BITSAdminでファイルをダウンロードしようとしています"),

        // certutil（証明書ツールの悪用）
        (new Regex(@"certutil.*-urlcache", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Certutil Download", "certutilでファイルをダウンロードしようとしています"),

        (new Regex(@"certutil.*-decode", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Certutil Decode", "certutilでエンコードされたファイルをデコードしようとしています"),

        // curl/wget + 実行パイプ
        (new Regex(@"curl.*\|\s*(powershell|cmd|bash|sh|iex)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Curl Pipe Exec", "curlでダウンロードしたものを直接実行しようとしています"),

        // regsvr32（DLLサイドローディング）
        (new Regex(@"regsvr32.*/(s|i).*https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Regsvr32 Remote", "regsvr32でリモートDLLを読み込もうとしています"),

        // rundll32
        (new Regex(@"rundll32.*https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Rundll32 Remote", "rundll32でリモートDLLを実行しようとしています"),

        // nslookup DNS型（2026年最新亜種）
        (new Regex(@"nslookup.*\|.*powershell", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "DNS Payload", "nslookupのDNS応答からペイロードを取得しようとしています（2026年新型攻撃）"),

        // finger.exe（CrashFix亜種 2026年）
        (new Regex(@"finger\s+\S+@\S+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Finger.exe Abuse", "finger.exeを悪用したコード実行の可能性（CrashFix亜種）"),

        // wscript/cscript + URL
        (new Regex(@"(wscript|cscript).*https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Script Host Remote", "Windows Script Hostでリモートスクリプトを実行しようとしています"),

        // msiexec リモート
        (new Regex(@"msiexec.*/i\s+https?://", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "MSI Remote Install", "リモートのMSIパッケージをインストールしようとしています"),
    ];

    // === 危険度: Suspicious（単体では合法だが注意が必要） ===
    private static readonly (Regex Pattern, string Category, string Description)[] SuspiciousPatterns =
    [
        // powershell 単独起動
        (new Regex(@"^powershell\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell", "PowerShellの起動が指示されています"),

        (new Regex(@"^pwsh\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "PowerShell Core", "PowerShell Coreの起動が指示されています"),

        // cmd /c
        (new Regex(@"cmd\s*/c\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "CMD Execute", "コマンドプロンプトでコマンドを実行しようとしています"),

        // ExecutionPolicy Bypass
        (new Regex(@"-ExecutionPolicy\s+Bypass", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Policy Bypass", "PowerShellの実行ポリシーを回避しようとしています"),

        (new Regex(@"-ep\s+bypass", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Policy Bypass", "PowerShellの実行ポリシーを回避しようとしています"),

        // NoProfile
        (new Regex(@"-NoP(rofile)?", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "No Profile", "PowerShellプロファイルなしで実行しようとしています"),

        // AppData/Temp パス参照
        (new Regex(@"(AppData|%TEMP%|%TMP%|\\Temp\\)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Temp Directory", "一時フォルダへのアクセスが含まれています"),

        // http/https URL含有
        (new Regex(@"https?://\S+\.(exe|ps1|bat|cmd|vbs|js|msi|dll|zip|7z|rar)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
         "Executable URL", "実行可能ファイルのURLが含まれています"),
    ];

    /// <summary>
    /// クリップボードの内容を検査し、最も危険度の高い脅威を返す。
    /// </summary>
    public static ThreatMatch? Analyze(string clipboardText)
    {
        if (string.IsNullOrWhiteSpace(clipboardText))
            return null;

        // 改行を正規化
        var text = clipboardText.Replace("\r\n", "\n").Replace("\r", "\n");

        // Critical パターンを最初にチェック
        foreach (var (pattern, category, description) in CriticalPatterns)
        {
            var match = pattern.Match(text);
            if (match.Success)
            {
                var fragment = ExtractFragment(text, match);
                return new ThreatMatch(ThreatLevel.Critical, category, description, fragment);
            }
        }

        // Suspicious パターン
        foreach (var (pattern, category, description) in SuspiciousPatterns)
        {
            var match = pattern.Match(text);
            if (match.Success)
            {
                var fragment = ExtractFragment(text, match);
                return new ThreatMatch(ThreatLevel.Suspicious, category, description, fragment);
            }
        }

        return null;
    }

    /// <summary>マッチ箇所の前後を含む断片を抽出（表示用）</summary>
    private static string ExtractFragment(string text, Match match)
    {
        const int contextChars = 40;
        int start = Math.Max(0, match.Index - contextChars);
        int end = Math.Min(text.Length, match.Index + match.Length + contextChars);
        var fragment = text[start..end];
        if (start > 0) fragment = "..." + fragment;
        if (end < text.Length) fragment += "...";
        return fragment;
    }
}
