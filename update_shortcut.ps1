$sh = New-Object -ComObject WScript.Shell

# 1. Update Public Desktop shortcut
try {
    $sc = $sh.CreateShortcut('C:\Users\Public\Desktop\Healing POS Desktop.lnk')
    $sc.TargetPath = 'C:\Users\PC 1\Downloads\Healing_POS_App\Healing POS Desktop.exe'
    $sc.WorkingDirectory = 'C:\Users\PC 1\Downloads\Healing_POS_App'
    $sc.Save()
    Write-Output "Public Desktop shortcut redirected successfully!"
} catch {
    Write-Output ("Public Desktop error: " + $_.Exception.Message)
}

# 2. Update User Desktop shortcut
try {
    $sc2 = $sh.CreateShortcut('C:\Users\PC 1\Desktop\Healing POS Desktop.lnk')
    $sc2.TargetPath = 'C:\Users\PC 1\Downloads\Healing_POS_App\Healing POS Desktop.exe'
    $sc2.WorkingDirectory = 'C:\Users\PC 1\Downloads\Healing_POS_App'
    $sc2.Save()
    Write-Output "User Desktop shortcut created successfully!"
} catch {
    Write-Output ("User Desktop error: " + $_.Exception.Message)
}

