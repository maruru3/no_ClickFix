namespace ClickFixGuard;

/// <summary>
/// システムトレイ常駐アプリケーション。
/// ClipboardMonitor + KeyboardHook を統合し、検知時に警告を表示。
/// </summary>
public sealed class TrayApplication : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly ClipboardMonitor _clipboardMonitor;
    private readonly KeyboardHook _keyboardHook;
    private bool _isShowingDialog;
    private int _blockedCount;
    private int _warningCount;

    public TrayApplication()
    {
        // クリップボード監視
        _clipboardMonitor = new ClipboardMonitor(intervalMs: 500);
        _clipboardMonitor.ThreatDetected += OnThreatDetected;
        _clipboardMonitor.ThreatCleared += OnThreatCleared;

        // キーボードフック
        _keyboardHook = new KeyboardHook(
            hasThreat: () => _clipboardMonitor.CurrentThreat != null,
            getThreatLevel: () => _clipboardMonitor.CurrentThreat?.Level ?? ThreatPatterns.ThreatLevel.Safe
        );
        _keyboardHook.DangerousWinRBlocked += OnDangerousKeyBlocked;
        _keyboardHook.DangerousWinXBlocked += OnDangerousKeyBlocked;

        // システムトレイ
        _trayIcon = new NotifyIcon
        {
            Icon = CreateShieldIcon(),
            Text = "ClickFixGuard - 監視中",
            Visible = true,
            ContextMenuStrip = CreateContextMenu()
        };

        // 起動
        _clipboardMonitor.Start();
        _keyboardHook.Install();

        _trayIcon.ShowBalloonTip(3000, "ClickFixGuard",
            "ClickFix攻撃からPCを保護しています。\nシステムトレイで常駐中。",
            ToolTipIcon.Info);
    }

    private void OnThreatDetected(ThreatPatterns.ThreatMatch threat)
    {
        // トレイアイコンを変更
        UpdateTrayStatus(threat.Level);

        if (threat.Level == ThreatPatterns.ThreatLevel.Critical)
        {
            _trayIcon.ShowBalloonTip(5000, "!! ClickFix攻撃を検知 !!",
                $"クリップボードに危険なコマンドが仕込まれています。\n" +
                $"カテゴリ: {threat.Category}\n" +
                $"Win+R を押さないでください！",
                ToolTipIcon.Error);
        }
        else
        {
            _trayIcon.ShowBalloonTip(3000, "注意: 不審なクリップボード",
                $"クリップボードに不審な内容があります。\n" +
                $"カテゴリ: {threat.Category}",
                ToolTipIcon.Warning);
        }
    }

    private void OnThreatCleared()
    {
        UpdateTrayStatus(ThreatPatterns.ThreatLevel.Safe);
    }

    private void OnDangerousKeyBlocked(string triggerKey)
    {
        if (_isShowingDialog) return;
        _isShowingDialog = true;

        var threat = _clipboardMonitor.CurrentThreat;
        if (threat == null)
        {
            _isShowingDialog = false;
            return;
        }

        if (threat.Level == ThreatPatterns.ThreatLevel.Critical)
            _blockedCount++;
        else
            _warningCount++;

        // 警告ダイアログ表示
        using var dialog = new WarningDialog(threat, _clipboardMonitor.CurrentClipboardText, triggerKey);
        var result = dialog.ShowDialog();

        if (dialog.ClearClipboardRequested)
        {
            _clipboardMonitor.ClearClipboard();
            _trayIcon.ShowBalloonTip(2000, "ClickFixGuard",
                "クリップボードをクリアしました。安全です。", ToolTipIcon.Info);
        }

        _isShowingDialog = false;
    }

    private void UpdateTrayStatus(ThreatPatterns.ThreatLevel level)
    {
        _trayIcon.Text = level switch
        {
            ThreatPatterns.ThreatLevel.Critical => "ClickFixGuard - !! 危険検知中 !!",
            ThreatPatterns.ThreatLevel.Suspicious => "ClickFixGuard - 注意: 不審な内容あり",
            _ => "ClickFixGuard - 監視中 (安全)"
        };
        _trayIcon.Icon = level switch
        {
            ThreatPatterns.ThreatLevel.Critical => CreateDangerIcon(),
            ThreatPatterns.ThreatLevel.Suspicious => CreateWarningIcon(),
            _ => CreateShieldIcon()
        };
    }

    private ContextMenuStrip CreateContextMenu()
    {
        var menu = new ContextMenuStrip();

        menu.Items.Add("ClickFixGuard v1.0", null, null!).Enabled = false;
        menu.Items.Add(new ToolStripSeparator());

        var statusItem = new ToolStripMenuItem("状態: 監視中") { Enabled = false };
        menu.Items.Add(statusItem);

        menu.Items.Add("クリップボードを今すぐチェック", null, (_, _) =>
        {
            var threat = _clipboardMonitor.CurrentThreat;
            if (threat != null)
            {
                MessageBox.Show(
                    $"!! 危険なクリップボード内容を検知中 !!\n\n" +
                    $"カテゴリ: {threat.Category}\n" +
                    $"説明: {threat.Description}\n" +
                    $"危険度: {threat.Level}\n\n" +
                    $"マッチ: {threat.MatchedFragment}",
                    "ClickFixGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                MessageBox.Show("クリップボードは安全です。", "ClickFixGuard",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        });

        menu.Items.Add("クリップボードをクリア", null, (_, _) =>
        {
            _clipboardMonitor.ClearClipboard();
            MessageBox.Show("クリップボードをクリアしました。", "ClickFixGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        });

        menu.Items.Add(new ToolStripSeparator());

        menu.Items.Add($"ブロック回数: {_blockedCount} / 警告回数: {_warningCount}", null, null!).Enabled = false;

        menu.Items.Add(new ToolStripSeparator());

        menu.Items.Add("終了", null, (_, _) =>
        {
            var result = MessageBox.Show(
                "ClickFixGuardを終了すると、ClickFix攻撃の検知が無効になります。\n終了しますか？",
                "ClickFixGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (result == DialogResult.Yes)
            {
                _trayIcon.Visible = false;
                _clipboardMonitor.Dispose();
                _keyboardHook.Dispose();
                Application.Exit();
            }
        });

        // メニューを開く度にカウンタ更新
        menu.Opening += (_, _) =>
        {
            foreach (ToolStripItem item in menu.Items)
            {
                if (item.Text?.StartsWith("ブロック回数") == true)
                    item.Text = $"ブロック回数: {_blockedCount} / 警告回数: {_warningCount}";
                if (item.Text?.StartsWith("状態") == true)
                {
                    var threat = _clipboardMonitor.CurrentThreat;
                    item.Text = threat != null
                        ? $"状態: {threat.Level} - {threat.Category}"
                        : "状態: 監視中 (安全)";
                }
            }
        };

        return menu;
    }

    // === シンプルなアイコン生成（外部リソース不要） ===

    private static Icon CreateShieldIcon()
    {
        var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        // 緑の盾
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.ForestGreen, points);
        g.DrawString("G", new Font("Segoe UI", 12, FontStyle.Bold), Brushes.White, 7, 6);
        return Icon.FromHandle(bmp.GetHicon());
    }

    private static Icon CreateWarningIcon()
    {
        var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.Orange, points);
        g.DrawString("!", new Font("Segoe UI", 14, FontStyle.Bold), Brushes.Black, 9, 4);
        return Icon.FromHandle(bmp.GetHicon());
    }

    private static Icon CreateDangerIcon()
    {
        var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.Red, points);
        g.DrawString("X", new Font("Segoe UI", 12, FontStyle.Bold), Brushes.White, 8, 6);
        return Icon.FromHandle(bmp.GetHicon());
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _trayIcon.Dispose();
            _clipboardMonitor.Dispose();
            _keyboardHook.Dispose();
        }
        base.Dispose(disposing);
    }
}
