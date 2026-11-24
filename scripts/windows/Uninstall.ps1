Add-Type -AssemblyName System.Windows.Forms
$root = $PSScriptRoot
$expected = Join-Path $env:LOCALAPPDATA 'Programs\ConnWatchDesktop\3.0.0'
if ([IO.Path]::GetFullPath($root) -ne [IO.Path]::GetFullPath($expected)) {
    [Windows.Forms.MessageBox]::Show('This uninstaller can only remove the installed ConnWatch 3.0.0 folder.','ConnWatch') | Out-Null
    exit 1
}
if ([Windows.Forms.MessageBox]::Show('Remove ConnWatch Network? Close the app first. Your saved monitoring data will be kept.','ConnWatch','YesNo','Question') -ne 'Yes') { exit }
try {
    $ws = New-Object -ComObject WScript.Shell
    foreach ($folder in @([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('Programs'))) {
        $link = Join-Path $folder 'ConnWatch Network.lnk'
        if ((Test-Path -LiteralPath $link) -and ($ws.CreateShortcut($link).TargetPath -eq (Join-Path $root 'ConnWatch.exe'))) {
            Remove-Item -LiteralPath $link -Force
        }
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ConnWatchNetwork' -Recurse -Force -ErrorAction SilentlyContinue
    [Windows.Forms.MessageBox]::Show('ConnWatch was removed. Your saved monitoring workspace has been kept.','ConnWatch') | Out-Null
} catch {
    [Windows.Forms.MessageBox]::Show(('Could not finish removing the app. Close ConnWatch and retry. ' + $_.Exception.Message),'ConnWatch') | Out-Null
}
