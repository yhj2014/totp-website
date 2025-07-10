<#
.SYNOPSIS
自动将 TOTP 认证器打包为 Windows EXE 文件
#>

# 检查是否以管理员身份运行
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "请以管理员身份运行此脚本！" -ForegroundColor Red
    exit
}

# 检查 Python 是否安装
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "未检测到 Python，请先安装 Python 3.8+ 并添加到 PATH" -ForegroundColor Red
    exit
}

# 检查 PyInstaller 是否安装
if (-not (pip show pyinstaller)) {
    Write-Host "正在安装 PyInstaller..."
    pip install pyinstaller
}

# 创建构建目录
$buildDir = "build_windows"
if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $buildDir | Out-Null

# 复制必要文件
Copy-Item "totp.py" -Destination $buildDir
Copy-Item "locales" -Destination $buildDir -Recurse

# 安装依赖
Write-Host "正在安装依赖库..."
pip install pyotp qrcode opencv-python pillow cryptography

# 开始打包
Write-Host "开始打包 EXE (这可能需要几分钟)..." -ForegroundColor Cyan
Set-Location $buildDir

pyinstaller `
    --onefile `
    --windowed `
    --name "TOTP_Authenticator" `
    --icon "NONE" `
    --add-data "locales;locales" `
    totp.py

# 整理文件
$distDir = "dist"
$outputDir = "../TOTP_Windows"
if (Test-Path $outputDir) {
    Remove-Item $outputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDir | Out-Null

Copy-Item "$distDir/*" -Destination $outputDir -Recurse
Copy-Item "locales" -Destination $outputDir -Recurse

# 清理临时文件
Remove-Item "build" -Recurse -Force
Remove-Item "dist" -Recurse -Force
Remove-Item "*.spec" -Force

Set-Location ..

Write-Host "`n打包完成！EXE 文件已保存到: $((Get-Item $outputDir).FullName)" -ForegroundColor Green
Write-Host "请将整个文件夹分发给用户使用" -ForegroundColor Yellow
