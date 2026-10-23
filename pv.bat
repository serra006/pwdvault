@echo off
rem pv 命令包装器：把 pv.py 挂成一个可以直接敲的命令。
rem
rem 按你的环境二选一（默认走 py 启动器，装了官方 Python 就有）：
rem   py -3     —— Windows 的 Python Launcher，会自动挑已装的 Python 3
rem   python    —— PATH 里有 python 时用这个
rem 两者都不行？就把下面那行换成你机器上 python.exe 的绝对路径，例如：
rem   "C:\Users\你\AppData\Local\Programs\Python\Python311\python.exe" "%~dp0pv.py" %*
rem
rem 用哪个解释器不重要，但**必须是 Python 3.9 及以上**。
setlocal
set "PYTHONIOENCODING=utf-8"

where py >nul 2>nul && (
    py -3 "%~dp0pv.py" %*
    exit /b %ERRORLEVEL%
)

where python >nul 2>nul && (
    python "%~dp0pv.py" %*
    exit /b %ERRORLEVEL%
)

echo [pv] 没找到 Python。请先安装 Python 3.9+，或编辑 pv.bat 把 python.exe 的绝对路径填进去。 >&2
exit /b 1
