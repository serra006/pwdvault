@echo off
rem ============================================================
rem  pwdvault 启动器 —— 双击就能用
rem
rem  双击本文件会：启动本地网页服务 -> 自动打开浏览器 -> 直接在网页里操作。
rem  不需要敲任何命令，也不需要知道 python.exe 装在哪。
rem
rem  不想看到这个黑窗口？双击同目录的 start-pwdvault.vbs，效果一样、没有窗口。
rem ============================================================
setlocal
set "PYTHONIOENCODING=utf-8"

cd /d "%~dp0"

echo 正在启动 pwdvault，浏览器马上会自动打开……
echo 想停下服务：关掉这个窗口，或在这里按 Ctrl+C。
echo.

rem 自动找 Python：先用 py 启动器（装官方 Python 就有），退回 python。
set "PV_LAUNCHER="
where py >nul 2>nul && set "PV_LAUNCHER=py -3"
if not defined PV_LAUNCHER (
    where python >nul 2>nul && set "PV_LAUNCHER=python"
)

if not defined PV_LAUNCHER (
    echo [pwdvault] 没找到 Python，请先安装 Python 3.10 以上版本，
    echo [pwdvault] 安装时勾选 "Add python.exe to PATH"，装完再双击本文件。
    echo.
    if not defined PV_NOPAUSE pause
    exit /b 1
)

%PV_LAUNCHER% "%~dp0pv.py" web
exit /b %ERRORLEVEL%
