# 编译 iptun GUI（使用系统自带 .NET Framework 4 编译器，零额外依赖）
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { throw "找不到 csc.exe" }

& $csc /nologo /target:winexe /platform:x64 `
    /win32manifest:"$here\app.manifest" `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Drawing.dll `
    /reference:System.Windows.Forms.dll `
    /reference:System.ServiceProcess.dll `
    /out:"$here\iptun-gui.exe" `
    "$here\IptunGui.cs"

if ($LASTEXITCODE -eq 0) {
    Write-Host "BUILD OK: $here\iptun-gui.exe" -ForegroundColor Green
}
