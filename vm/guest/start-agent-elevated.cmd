@echo off
rem Run from HKCU RunOnce in the autologon session by vm\bootstrap-vm.ps1. With ConsentPromptBehaviorAdmin=0
rem the RunAs request is granted silently and starts the elevated rig agent.
powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\cr\agent.ps1'"
