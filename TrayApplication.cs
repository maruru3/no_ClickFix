using System.Runtime.InteropServices;

namespace ClickFixGuard;

/// <summary>
/// システムトレイ常駐アプリケーション。
/// ClipboardMonitor + KeyboardHook を統合し、検知時に警告を表示。
/// </summary>
public sealed class TrayApplication : ApplicationContext
{
    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    private readonly NotifyIcon _trayIcon;
    private readonly ClipboardMonitor _clipboardMonitor;
    private readonly KeyboardHook _keyboardHook;
    private bool _isShowingDialog;
    private int _blockedCount;
    private int _warningCount;

    // アイコンは起動時に1回だけ生成して使い回す（GDIハンドルリーク防止）
    private readonly Icon _iconSafe;
    private readonly Icon _iconWarning;
    private readonly Icon _iconDanger;

    public TrayApplication()
    {
        // アイコン生成（1回だけ）
        _iconSafe = CreateShieldIcon();
        _iconWarning = CreateWarningIcon();
        _iconDanger = CreateDangerIcon();

        // クリップボード監視
        _clipboardMonitor = new ClipboardMonitor(intervalMs: 500);
        _clipboardMonitor.ThreatDetected += OnThreatDetected;
        _clipboardMonitor.ThreatCleared += OnThreatCleared;

        // キーボードフック
        _keyboardHook = new KeyboardHook(
            hasThreat: () => _clipboardMonitor.CurrentThreat != null,
            getThreatLevel: () => _clipboardMonitor.CurrentThreat?.Level ?? ThreatPatterns.ThreatLevel.Safe
        );
        _keyboardHook.DangerousWinRDetected += OnDangerousKeyDetected;
        _keyboardHook.DangerousWinXDetected += OnDangerousKeyDetected;

        // システムトレイ
        _trayIcon = new NotifyIcon
        {
            Icon = _iconSafe,
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

    private void OnDangerousKeyDetected(string triggerKey)
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
        else if (dialog.AddToAllowListRequested && dialog.AllowListPattern != null)
        {
            _clipboardMonitor.AllowList.AddPattern(dialog.AllowListPattern);
            _clipboardMonitor.ClearClipboard();
            _trayIcon.ShowBalloonTip(3000, "ClickFixGuard",
                $"許可リストに追加しました。\nパターン: {dialog.AllowListPattern}",
                ToolTipIcon.Info);
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
            ThreatPatterns.ThreatLevel.Critical => _iconDanger,
            ThreatPatterns.ThreatLevel.Suspicious => _iconWarning,
            _ => _iconSafe
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

        menu.Items.Add("許可リスト編集...", null, (_, _) =>
        {
            ShowAllowListEditor();
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

    private void ShowAllowListEditor()
    {
        var allowList = _clipboardMonitor.AllowList;
        using var form = new Form
        {
            Text = "ClickFixGuard - 許可リスト編集",
            Size = new Size(500, 400),
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = Color.FromArgb(30, 30, 30),
            ForeColor = Color.White
        };

        var label = new Label
        {
            Text = "許可リストのパターン（正規表現、1行1パターン）:",
            Font = new Font("Segoe UI", 10),
            Location = new Point(15, 10),
            AutoSize = true
        };

        var textBox = new TextBox
        {
            Text = string.Join(Environment.NewLine, allowList.Patterns),
            Font = new Font("Consolas", 10),
            ForeColor = Color.Lime,
            BackColor = Color.FromArgb(20, 20, 20),
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(15, 35),
            Size = new Size(455, 240),
            WordWrap = false
        };

        var enabledCheck = new CheckBox
        {
            Text = "許可リストを有効にする",
            Font = new Font("Segoe UI", 10),
            Checked = allowList.Enabled,
            Location = new Point(15, 285),
            AutoSize = true,
            ForeColor = Color.White
        };

        var saveButton = new Button
        {
            Text = "保存して閉じる",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            BackColor = Color.FromArgb(0, 100, 50),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Location = new Point(15, 320),
            Size = new Size(200, 35)
        };
        saveButton.Click += (_, _) =>
        {
            // パターンを更新
            var newPatterns = textBox.Text
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim())
                .Where(p => !string.IsNullOrEmpty(p))
                .ToList();

            // 既存パターンをクリアして再追加
            while (allowList.Patterns.Count > 0)
                allowList.RemovePattern(allowList.Patterns[0]);
            foreach (var p in newPatterns)
                allowList.AddPattern(p);

            allowList.SetEnabled(enabledCheck.Checked);

            MessageBox.Show($"{newPatterns.Count}件のパターンを保存しました。",
                "ClickFixGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            form.Close();
        };

        var cancelButton = new Button
        {
            Text = "キャンセル",
            Font = new Font("Segoe UI", 10),
            BackColor = Color.FromArgb(60, 60, 60),
            ForeColor = Color.LightGray,
            FlatStyle = FlatStyle.Flat,
            Location = new Point(230, 320),
            Size = new Size(140, 35)
        };
        cancelButton.Click += (_, _) => form.Close();

        form.Controls.AddRange([label, textBox, enabledCheck, saveButton, cancelButton]);
        form.ShowDialog();
    }

    // === アイコン生成（起動時に1回だけ呼ばれる） ===

    private static Icon CreateShieldIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.ForestGreen, points);
        g.DrawString("G", new Font("Segoe UI", 12, FontStyle.Bold), Brushes.White, 7, 6);
        return CloneAndReleaseHicon(bmp);
    }

    private static Icon CreateWarningIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.Orange, points);
        g.DrawString("!", new Font("Segoe UI", 14, FontStyle.Bold), Brushes.Black, 9, 4);
        return CloneAndReleaseHicon(bmp);
    }

    private static Icon CreateDangerIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var points = new Point[] {
            new(16, 2), new(28, 8), new(28, 18), new(16, 30), new(4, 18), new(4, 8)
        };
        g.FillPolygon(Brushes.Red, points);
        g.DrawString("X", new Font("Segoe UI", 12, FontStyle.Bold), Brushes.White, 8, 6);
        return CloneAndReleaseHicon(bmp);
    }

    /// <summary>BitmapからIcon生成後、元HICONを確実に解放する</summary>
    private static Icon CloneAndReleaseHicon(Bitmap bmp)
    {
        IntPtr hIcon = IntPtr.Zero;
        try
        {
            hIcon = bmp.GetHicon();
            using var temp = Icon.FromHandle(hIcon);
            return (Icon)temp.Clone();
        }
        finally
        {
            if (hIcon != IntPtr.Zero)
                DestroyIcon(hIcon);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _trayIcon.Dispose();
            _clipboardMonitor.Dispose();
            _keyboardHook.Dispose();
            _iconSafe.Dispose();
            _iconWarning.Dispose();
            _iconDanger.Dispose();
        }
        base.Dispose(disposing);
    }
}
