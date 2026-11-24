$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'C:\Users\PC 1\Downloads\Healing_POS_App\Healing POS Desktop.exe'
$psi.UseShellExecute = $false
$psi.EnvironmentVariables.Remove('ELECTRON_RUN_AS_NODE')
$proc = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 3
Get-Process -Id $proc.Id -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, MainWindowTitle, Responding, HasExited

