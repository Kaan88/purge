@echo off
rem Run in the VM's logged-in session; asks UAC once, then agent.ps1 runs elevated in the background.
powershell -NoProfile -WindowStyle Hidden -Command "Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\cr\agent.ps1'"
