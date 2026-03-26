using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClickFixGuard;

/// <summary>
/// 許可リスト管理。正当なコマンドパターンを登録し、誤検知を抑制する。
/// allowlist.json をClickFixGuard.exeと同じフォルダに自動生成・管理。
/// </summary>
public sealed class AllowList
{
    private readonly string _filePath;
    private AllowListData _data;
    private List<Regex> _compiledPatterns = [];

    /// <summary>現在の許可パターン一覧</summary>
    public IReadOnlyList<string> Patterns => _data.Patterns;

    /// <summary>許可リストが有効か</summary>
    public bool Enabled => _data.Enabled;

    public AllowList()
    {
        var exeDir = AppContext.BaseDirectory;
        _filePath = Path.Combine(exeDir, "allowlist.json");
        _data = new AllowListData();
        Load();
    }

    /// <summary>クリップボード内容が許可リストにマッチするか</summary>
    public bool IsAllowed(string clipboardText)
    {
        if (!_data.Enabled || string.IsNullOrWhiteSpace(clipboardText))
            return false;

        foreach (var pattern in _compiledPatterns)
        {
            if (pattern.IsMatch(clipboardText))
                return true;
        }
        return false;
    }

    /// <summary>新しいパターンを許可リストに追加</summary>
    public void AddPattern(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return;

        // 重複チェック
        if (_data.Patterns.Contains(pattern, StringComparer.OrdinalIgnoreCase))
            return;

        _data.Patterns.Add(pattern);
        CompilePatterns();
        Save();
    }

    /// <summary>パターンを許可リストから削除</summary>
    public void RemovePattern(string pattern)
    {
        var index = _data.Patterns.FindIndex(p => p.Equals(pattern, StringComparison.OrdinalIgnoreCase));
        if (index >= 0)
        {
            _data.Patterns.RemoveAt(index);
            CompilePatterns();
            Save();
        }
    }

    /// <summary>許可リストの有効/無効を切り替え</summary>
    public void SetEnabled(bool enabled)
    {
        _data.Enabled = enabled;
        Save();
    }

    /// <summary>ファイルから読み込み</summary>
    public void Load()
    {
        try
        {
            if (File.Exists(_filePath))
            {
                var json = File.ReadAllText(_filePath);
                _data = JsonSerializer.Deserialize<AllowListData>(json) ?? new AllowListData();
            }
            else
            {
                _data = CreateDefault();
                Save();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ClickFixGuard] AllowList load error: {ex.Message}");
            _data = new AllowListData();
        }
        CompilePatterns();
    }

    /// <summary>ファイルに保存</summary>
    private void Save()
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(_data, options);
            File.WriteAllText(_filePath, json);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ClickFixGuard] AllowList save error: {ex.Message}");
        }
    }

    /// <summary>パターン文字列をRegexにコンパイル</summary>
    private void CompilePatterns()
    {
        _compiledPatterns = [];
        foreach (var pattern in _data.Patterns)
        {
            try
            {
                _compiledPatterns.Add(new Regex(pattern,
                    RegexOptions.IgnoreCase | RegexOptions.Compiled,
                    TimeSpan.FromMilliseconds(100))); // ReDoS防止タイムアウト
            }
            catch (RegexParseException ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"[ClickFixGuard] Invalid allowlist regex '{pattern}': {ex.Message}");
            }
        }
    }

    /// <summary>デフォルトの許可リスト（開発者向けの安全なパターン）</summary>
    private static AllowListData CreateDefault()
    {
        return new AllowListData
        {
            Enabled = true,
            Patterns =
            [
                @"^cmd /c echo\b",          // echo コマンド（無害）
                @"^dotnet\b",                // .NET CLI
                @"^git\b",                   // Git コマンド
                @"^npm\b",                   // npm コマンド
                @"^node\b",                  // Node.js
                @"^python\b",               // Python（ダウンロード系パターンはCriticalで先に引っかかる）
                @"^code\b",                  // VS Code
            ]
        };
    }

    /// <summary>クリップボード内容からエスケープ済みの許可パターンを生成</summary>
    public static string CreateExactPattern(string clipboardText)
    {
        // 先頭40文字をエスケープしてパターン化
        var truncated = clipboardText.Length > 40 ? clipboardText[..40] : clipboardText;
        return "^" + Regex.Escape(truncated);
    }
}

/// <summary>allowlist.json のデータ構造</summary>
public class AllowListData
{
    public bool Enabled { get; set; } = true;
    public List<string> Patterns { get; set; } = [];
}
