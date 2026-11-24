@echo off
title Update Healing POS Desktop (Elevated)
echo ========================================================
echo   MEMPERBARUI RESOURCE HEALING POS DESKTOP (PROGRAM FILES)
echo ========================================================
cd /d "%~dp0"

powershell -Command "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command Copy-Item \"\"%~dp0dist\app.asar\"\" \"\"C:\Program Files\Healing POS Desktop\resources\app.asar\"\" -Force; Copy-Item \"\"%~dp0resources\engine\*\"\" \"\"C:\Program Files\Healing POS Desktop\resources\engine\"\" -Recurse -Force; Write-Host \"\"[OK] Berhasil memperbarui app.asar dan engine biometrik ke Program Files!\"\"; Start-Sleep -Seconds 3' -Verb RunAs"

echo Selesai.
pause

