@echo off
title PURE PERFORMANCE WINDOWS 10 DEBLOATER
echo ========================
echo PURE FPS STRIPPER SCRIPT - FINAL FORM
echo ========================
echo Author: You + ChatGPT | Version: Final Merge
echo.

:: --------- CHECK ADMIN ---------
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo Run this script as Administrator!
    pause
    exit
)

:: --------- AUTO LOGIN ---------
set "username=%USERNAME%"
set "password="
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUsername /t REG_SZ /d "%username%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d "%password%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName /t REG_SZ /d "%COMPUTERNAME%" /f

:: --------- STRIP SERVICES ---------
echo Disabling unnecessary services...
set KEEP_SERVICES="Audiosrv AudioEndpointBuilder Dhcp Dnscache EventLog LSM NlaSvc nsi PlugPlay Power RpcSs Schedule ShellHWDetection Themes Winmgmt WlanSvc W32Time"
for /f "tokens=*" %%s in ('sc query state^= all ^| findstr /R "^SERVICE_NAME:"') do (
    set "svc=%%s"
    setlocal enabledelayedexpansion
    for /f "tokens=2 delims=:" %%a in ("!svc!") do (
        set "service=%%a"
        set "service=!service:~1!"
        echo !KEEP_SERVICES! | find /I "!service!" >nul
        if errorlevel 1 (
            echo Disabling !service!
            sc stop "!service!" >nul 2>&1
            sc config "!service!" start= disabled >nul 2>&1
        )
    )
    endlocal
)

:: --------- REMOVE STORE / UWP / XBOX ---------
echo Removing Microsoft Store, Xbox, and all UWP apps...
powershell -command "Get-AppxPackage -AllUsers | Remove-AppxPackage"
powershell -command "Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online"
powershell -command "Get-AppxPackage Microsoft.WindowsStore -AllUsers | Remove-AppxPackage"
powershell -command "Get-AppxPackage Microsoft.Xbox* -AllUsers | Remove-AppxPackage"
powershell -command "Get-AppxProvisionedPackage -Online | where {$_.DisplayName -like '*Xbox*' -or $_.DisplayName -like '*Store*'} | Remove-AppxProvisionedPackage -Online"

:: --------- DISABLE VISUAL EFFECTS ---------
echo Disabling all animations and visual effects...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
reg add "HKCU\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f

:: --------- GAME / FPS TWEAKS ---------
echo Disabling GameBar, DVR and fullscreen optimizations...
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v value /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "*" /t REG_SZ /d "~ DISABLEDXMAXIMIZEDWINDOWEDMODE" /f

:: Enable HAGS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t REG_DWORD /d 2 /f

:: --------- POWER: ULTIMATE PERFORMANCE ---------
echo Enabling Ultimate Performance power plan...
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61

:: --------- MOUSE & KEYBOARD TWEAKS ---------
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f

:: --------- WIFI PERFORMANCE TWEAKS ---------
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Network\Connections" /v RandomHardwareAddressEnabled /t REG_DWORD /d 0 /f
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global ecncapability=disabled

:: --------- SYSTEM CLEANUP TWEAKS ---------
echo Disabling system-level clutter...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutoTrayNotify /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

:: --------- CLEAN TEMP FILES ---------
echo Cleaning up system temp files...
del /q /f /s "%TEMP%\*" >nul 2>&1
del /q /f /s "C:\Windows\Temp\*" >nul 2>&1

:: --------- FINISHED ---------
echo.
echo ✅ DONE. System is now stripped to the bone and optimized for max FPS.
echo 🔁 REBOOT RECOMMENDED.
pause
