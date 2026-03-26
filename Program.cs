namespace ClickFixGuard;

/// <summary>
/// ClickFixGuard エントリポイント。
/// システムトレイ常駐でClickFix攻撃を検知・防御する。
/// </summary>
internal static class Program
{
    [STAThread]
    static void Main()
    {
        // 多重起動防止
        using var mutex = new Mutex(true, "ClickFixGuard_SingleInstance", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("ClickFixGuardは既に起動しています。\nシステムトレイを確認してください。",
                "ClickFixGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);

        Application.Run(new TrayApplication());
    }
}
