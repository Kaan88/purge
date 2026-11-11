@echo off
rem One-off elevated command in the VM session: elevate.cmd <command line>. Needs one UAC approval.
powershell -NoProfile -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c %*'"
