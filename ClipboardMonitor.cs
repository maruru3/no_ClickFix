using System.Runtime.InteropServices;

namespace ClickFixGuard;

/// <summary>
/// クリップボードの内容を定期的に監視し、危険なパターンを検知するエンジン。
/// WinForms Timer + Clipboard.GetText() でポーリング。
/// </summary>
public sealed class ClipboardMonitor : IDisposable
{
    private readonly System.Windows.Forms.Timer _timer;
    private readonly AllowList _allowList;
    private string _lastClipboardText = "";
    private ThreatPatterns.ThreatMatch? _currentThreat;

    /// <summary>危険なクリップボード内容が検知された</summary>
    public event Action<ThreatPatterns.ThreatMatch>? ThreatDetected;

    /// <summary>クリップボードが安全な状態に戻った</summary>
    public event Action? ThreatCleared;

    /// <summary>現在検知中の脅威</summary>
    public ThreatPatterns.ThreatMatch? CurrentThreat => _currentThreat;

    /// <summary>現在のクリップボード内容</summary>
    public string CurrentClipboardText => _lastClipboardText;

    /// <summary>許可リストへのアクセス</summary>
    public AllowList AllowList => _allowList;

    public ClipboardMonitor(int intervalMs = 500, AllowList? allowList = null)
    {
        _allowList = allowList ?? new AllowList();
        _timer = new System.Windows.Forms.Timer { Interval = intervalMs };
        _timer.Tick += OnTimerTick;
    }

    public void Start() => _timer.Start();
    public void Stop() => _timer.Stop();

    private void OnTimerTick(object? sender, EventArgs e)
    {
        try
        {
            string text = "";
            if (Clipboard.ContainsText())
            {
                text = Clipboard.GetText();
            }

            // 前回と同じなら無視
            if (text == _lastClipboardText)
                return;

            _lastClipboardText = text;

            // 許可リストに一致する場合はスキップ
            if (_allowList.IsAllowed(text))
            {
                if (_currentThreat != null)
                {
                    _currentThreat = null;
                    ThreatCleared?.Invoke();
                }
                return;
            }

            var threat = ThreatPatterns.Analyze(text);
            if (threat != null)
            {
                _currentThreat = threat;
                ThreatDetected?.Invoke(threat);
            }
            else if (_currentThreat != null)
            {
                _currentThreat = null;
                ThreatCleared?.Invoke();
            }
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            // クリップボードが他プロセスにロック中 — 次回ポーリングでリトライ
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ClickFixGuard] Clipboard poll error: {ex.Message}");
        }
    }

    /// <summary>危険なクリップボード内容をクリアする</summary>
    public void ClearClipboard()
    {
        try
        {
            Clipboard.Clear();
            _lastClipboardText = "";
            bool hadThreat = _currentThreat != null;
            _currentThreat = null;
            if (hadThreat)
                ThreatCleared?.Invoke();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ClickFixGuard] ClearClipboard failed: {ex.Message}");
        }
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Dispose();
    }
}
