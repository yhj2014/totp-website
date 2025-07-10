<#
.SYNOPSIS
自动将 TOTP 认证器打包为 Android APK
#>

# 检查是否安装 Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "未检测到 Python，请先安装 Python 3.8+ 并添加到 PATH" -ForegroundColor Red
    exit
}

# 检查是否安装 BeeWare
if (-not (pip show briefcase)) {
    Write-Host "正在安装 BeeWare 工具链..."
    pip install briefcase
}

# 初始化项目 (如果尚未初始化)
if (-not (Test-Path "pyproject.toml")) {
    Write-Host "初始化 BeeWare 项目..."
    briefcase new
}

# 修改 pyproject.toml 添加 Android 配置
$pyprojectContent = @"
[build-system]
requires = ["briefcase"]

[tool.briefcase]
project_name = "TOTP Authenticator"
bundle = "com.example.totp"
version = "1.0.0"
url = "https://example.com/totp"
license = "MIT"
author = "Your Name"
author_email = "your@email.com"

[tool.briefcase.app.totp]
formal_name = "TOTP Authenticator"
description = "A TOTP authenticator app with biometric support"
sources = ["totp.py"]
requires = [
    "pyotp>=2.6.0",
    "qrcode>=7.3.1",
    "opencv-python-headless>=4.5.5",  # 使用无头版本
    "Pillow>=9.0.0",
    "cryptography>=36.0.0",
    "android-auto-play-opencv>=4.5.3"  # 简化OpenCV Android集成
]

[tool.briefcase.android.totp]
requires = [
    "pyjnius",
    "android"
]
permissions = [
    "android.permission.CAMERA",
    "android.permission.USE_FINGERPRINT",
    "android.permission.USE_BIOMETRIC"
]
"@

Set-Content -Path "pyproject.toml" -Value $pyprojectContent

# 创建构建目录
$buildDir = "build_android"
if (Test-Path $buildDir) {
    Remove-Item $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $buildDir | Out-Null

# 复制必要文件
Copy-Item "totp.py" -Destination $buildDir
Copy-Item "locales" -Destination $buildDir -Recurse

# 安装依赖
Write-Host "正在安装 Android 依赖..."
pip install pyjnius android

# 开始打包
Write-Host "开始打包 APK (这可能需要10-20分钟)..." -ForegroundColor Cyan
Set-Location $buildDir

briefcase create android
briefcase build android
briefcase run android -d

# 整理输出文件
$outputDir = "../TOTP_Android"
if (Test-Path $outputDir) {
    Remove-Item $outputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $outputDir | Out-Null

Copy-Item "android/*.apk" -Destination $outputDir
Copy-Item "android/gradlew" -Destination $outputDir -Recurse

Set-Location ..

Write-Host "`n打包完成！APK 文件已保存到: $((Get-Item $outputDir).FullName)" -ForegroundColor Green
Write-Host "请将 APK 文件安装到 Android 设备" -ForegroundColor Yellow
Write-Host "`n注意：首次运行需要配置 Android SDK 和 NDK" -ForegroundColor Magenta
