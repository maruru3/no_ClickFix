using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClickFixGuard;

/// <summary>
/// 低レベルキーボードフック（SetWindowsHookEx）で Win+R / Win+X を検知。
/// クリップボードに危険パターンがある状態でこれらのキーが押されたら、
/// キー入力をブロックして警告を表示する。
/// </summary>
public sealed class KeyboardHook : IDisposable
{
    // Win32 API
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const int VK_LWIN = 0x5B;
    private const int VK_RWIN = 0x5C;

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    private IntPtr _hookId = IntPtr.Zero;
    private readonly LowLevelKeyboardProc _hookProc;
    private readonly Func<bool> _hasThreat;
    private readonly Func<ThreatPatterns.ThreatLevel> _getThreatLevel;

    /// <summary>Win+R が危険な状態で検知された（Criticalならブロック、Suspiciousなら警告のみ）</summary>
    public event Action<string>? DangerousWinRDetected;

    /// <summary>Win+X が危険な状態で検知された（Criticalならブロック、Suspiciousなら警告のみ）</summary>
    public event Action<string>? DangerousWinXDetected;

    /// <param name="hasThreat">現在クリップボードに脅威があるか</param>
    /// <param name="getThreatLevel">現在の脅威レベル</param>
    public KeyboardHook(Func<bool> hasThreat, Func<ThreatPatterns.ThreatLevel> getThreatLevel)
    {
        _hasThreat = hasThreat;
        _getThreatLevel = getThreatLevel;
        _hookProc = HookCallback;
    }

    public void Install()
    {
        using var curProcess = Process.GetCurrentProcess();
        using var curModule = curProcess.MainModule!;
        _hookId = SetWindowsHookEx(WH_KEYBOARD_LL, _hookProc,
            GetModuleHandle(curModule.ModuleName), 0);

        if (_hookId == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Failed to install keyboard hook. Error: {Marshal.GetLastWin32Error()}");
    }

    private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
        {
            var hookStruct = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            bool winKeyDown = IsWinKeyDown();

            if (winKeyDown && _hasThreat())
            {
                var level = _getThreatLevel();

                // Win+R (Run ダイアログ)
                if (hookStruct.vkCode == 'R')
                {
                    if (level == ThreatPatterns.ThreatLevel.Critical)
                    {
                        // Critical: キー入力をブロック
                        DangerousWinRDetected?.Invoke("Win+R");
                        return (IntPtr)1; // ブロック
                    }
                    else if (level == ThreatPatterns.ThreatLevel.Suspicious)
                    {
                        // Suspicious: 警告のみ（ブロックしない）
                        DangerousWinRDetected?.Invoke("Win+R");
                    }
                }

                // Win+X (Quick Access Menu → PowerShell/Terminal)
                if (hookStruct.vkCode == 'X')
                {
                    if (level == ThreatPatterns.ThreatLevel.Critical)
                    {
                        DangerousWinXDetected?.Invoke("Win+X");
                        return (IntPtr)1; // ブロック
                    }
                    else if (level == ThreatPatterns.ThreatLevel.Suspicious)
                    {
                        DangerousWinXDetected?.Invoke("Win+X");
                    }
                }
            }
        }

        return CallNextHookEx(_hookId, nCode, wParam, lParam);
    }

    private static bool IsWinKeyDown()
    {
        return (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0
            || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0;
    }

    public void Dispose()
    {
        if (_hookId != IntPtr.Zero)
        {
            UnhookWindowsHookEx(_hookId);
            _hookId = IntPtr.Zero;
        }
    }
}
