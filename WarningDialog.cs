namespace ClickFixGuard;

/// <summary>
/// ClickFix攻撃の警告ダイアログ。
/// 危険なクリップボード内容とキー操作を検知した際に表示。
/// </summary>
public sealed class WarningDialog : Form
{
    private readonly ThreatPatterns.ThreatMatch _threat;
    private readonly string _clipboardContent;
    private readonly string _triggerKey;

    /// <summary>ユーザーが「クリップボードをクリア」を選んだ</summary>
    public bool ClearClipboardRequested { get; private set; }

    public WarningDialog(ThreatPatterns.ThreatMatch threat, string clipboardContent, string triggerKey)
    {
        _threat = threat;
        _clipboardContent = clipboardContent;
        _triggerKey = triggerKey;
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        // フォーム設定
        Text = "ClickFixGuard - セキュリティ警告";
        Size = new Size(620, 520);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        BackColor = _threat.Level == ThreatPatterns.ThreatLevel.Critical
            ? Color.FromArgb(60, 0, 0)
            : Color.FromArgb(60, 50, 0);
        ForeColor = Color.White;
        ShowInTaskbar = true;
        Icon = SystemIcons.Warning;

        var headerColor = _threat.Level == ThreatPatterns.ThreatLevel.Critical
            ? Color.FromArgb(220, 40, 40)
            : Color.FromArgb(220, 180, 0);

        // ヘッダー（警告アイコン＋タイトル）
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 60,
            BackColor = headerColor,
            Padding = new Padding(10)
        };

        var headerLabel = new Label
        {
            Text = _threat.Level == ThreatPatterns.ThreatLevel.Critical
                ? "!! 危険な操作を検知・ブロックしました !!"
                : "! 注意: 不審なクリップボード内容を検知 !",
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor = Color.White,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleCenter
        };
        headerPanel.Controls.Add(headerLabel);

        // 説明パネル
        var descPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80,
            Padding = new Padding(15, 10, 15, 5)
        };

        var descLabel = new Label
        {
            Text = $"あなたが {_triggerKey} を押そうとした時、クリップボードに危険なコマンドが\n" +
                   $"仕込まれていることを検知しました。\n\n" +
                   $"これは「ClickFix」と呼ばれるサイバー攻撃の可能性があります。\n" +
                   $"Webサイトの指示に従って貼り付け・実行しないでください。",
            Font = new Font("Segoe UI", 10),
            ForeColor = Color.FromArgb(255, 220, 220),
            Dock = DockStyle.Fill,
            AutoSize = false
        };
        descPanel.Controls.Add(descLabel);

        // 脅威詳細
        var detailGroup = new GroupBox
        {
            Text = "検知された脅威",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.White,
            Dock = DockStyle.Top,
            Height = 100,
            Padding = new Padding(10, 5, 10, 5)
        };

        var detailLabel = new Label
        {
            Text = $"カテゴリ: {_threat.Category}\n" +
                   $"説明: {_threat.Description}\n" +
                   $"危険度: {(_threat.Level == ThreatPatterns.ThreatLevel.Critical ? "Critical (極めて危険)" : "Suspicious (要注意)")}",
            Font = new Font("Segoe UI", 9),
            ForeColor = Color.FromArgb(255, 200, 200),
            Dock = DockStyle.Fill,
            AutoSize = false
        };
        detailGroup.Controls.Add(detailLabel);

        // クリップボード内容表示
        var clipGroup = new GroupBox
        {
            Text = "クリップボードに仕込まれていたコマンド",
            Font = new Font("Segoe UI", 10, FontStyle.Bold),
            ForeColor = Color.White,
            Dock = DockStyle.Top,
            Height = 100,
            Padding = new Padding(10, 5, 10, 5)
        };

        var clipText = new TextBox
        {
            Text = TruncateText(_clipboardContent, 500),
            Font = new Font("Consolas", 9),
            ForeColor = Color.Lime,
            BackColor = Color.FromArgb(30, 30, 30),
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            WordWrap = true
        };
        clipGroup.Controls.Add(clipText);

        // ボタンパネル
        var buttonPanel = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 60,
            Padding = new Padding(15, 10, 15, 10)
        };

        var clearButton = new Button
        {
            Text = "クリップボードをクリアして閉じる（推奨）",
            Font = new Font("Segoe UI", 11, FontStyle.Bold),
            BackColor = Color.FromArgb(0, 120, 60),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(340, 40),
            Location = new Point(15, 10),
            Cursor = Cursors.Hand
        };
        clearButton.Click += (_, _) =>
        {
            ClearClipboardRequested = true;
            DialogResult = DialogResult.OK;
            Close();
        };

        var ignoreButton = new Button
        {
            Text = "無視して閉じる",
            Font = new Font("Segoe UI", 10),
            BackColor = Color.FromArgb(80, 80, 80),
            ForeColor = Color.LightGray,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(200, 40),
            Location = new Point(380, 10),
            Cursor = Cursors.Hand
        };
        ignoreButton.Click += (_, _) =>
        {
            ClearClipboardRequested = false;
            DialogResult = DialogResult.Cancel;
            Close();
        };

        buttonPanel.Controls.Add(clearButton);
        buttonPanel.Controls.Add(ignoreButton);

        // コントロール追加（下から順に）
        Controls.Add(buttonPanel);
        Controls.Add(clipGroup);
        Controls.Add(detailGroup);
        Controls.Add(descPanel);
        Controls.Add(headerPanel);
    }

    private static string TruncateText(string text, int maxLength)
    {
        if (string.IsNullOrEmpty(text)) return "(empty)";
        return text.Length <= maxLength ? text : text[..maxLength] + "\n... (truncated)";
    }
}
