' ============================================================
'  pwdvault 静默启动器 —— 双击后不弹黑窗口
'
'  它做的事和 start-pwdvault.bat 完全一样：启动本地网页服务并打开浏览器。
'  区别是没有控制台窗口：服务在后台跑，你只会看到浏览器被打开。
'
'  想停服务：在任务管理器里结束 python.exe；
'  或者改用 start-pwdvault.bat（有窗口，关掉窗口就停）。
'
'  两个文件任选一个即可，不用都双击。
' ============================================================

Option Explicit

Dim shell, fso, here, bat

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' 路径由脚本自身位置推导，不写死任何具体目录
here = fso.GetParentFolderName(WScript.ScriptFullName)
bat = fso.BuildPath(here, "start-pwdvault.bat")

If Not fso.FileExists(bat) Then
    WScript.Echo "没找到 start-pwdvault.bat，请把这两个文件放在同一个目录里。"
    WScript.Quit 1
End If

' 隐藏模式下关掉 pause：否则万一没装 Python，会留下一个看不见又停不下来的窗口
shell.Environment("PROCESS")("PV_NOPAUSE") = "1"

' 第二个参数 0 = 隐藏窗口；第三个参数 False = 不等待它结束
shell.Run """" & bat & """", 0, False
