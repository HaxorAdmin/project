//go:build windows
package main

import (
 "archive/zip"
 "bytes"
 _ "embed"
 "fmt"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "syscall"
 "unsafe"
)
//go:embed payload.zip
var payload []byte
var box=syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
func message(body string,flags uintptr) uintptr {
 b,_:=syscall.UTF16PtrFromString(body);t,_:=syscall.UTF16PtrFromString("ConnWatch Network Setup")
 result,_,_:=box.Call(0,uintptr(unsafe.Pointer(b)),uintptr(unsafe.Pointer(t)),flags);return result
}
func quote(s string)string{return "'"+strings.ReplaceAll(s,"'","''")+"'"}
func install() error {
 local:=os.Getenv("LOCALAPPDATA");if local==""{return fmt.Errorf("Windows LOCALAPPDATA is unavailable")}
 root:=filepath.Join(local,"Programs","ConnWatchDesktop","3.0.0")
 if message("Install ConnWatch Network 3.0.0 for this Windows user?\n\nDeveloped by ZakirUllah\n\nA desktop and Start menu shortcut will be created. Your monitoring data stays local. No administrator access or separate Python installation is needed.\n\nClose an existing ConnWatch window before continuing.\n\nInstall folder:\n"+root,0x24)!=6{return nil}
 archive,err:=zip.NewReader(bytes.NewReader(payload),int64(len(payload)));if err!=nil{return err}
 for _,file:=range archive.File {
  name:=filepath.Clean(filepath.FromSlash(file.Name))
  if filepath.VolumeName(name)!=""||filepath.IsAbs(name)||name==".."||strings.HasPrefix(name,".."+string(os.PathSeparator)){return fmt.Errorf("unsafe package path")}
  target:=filepath.Join(root,name)
  if file.FileInfo().IsDir(){if err=os.MkdirAll(target,0755);err!=nil{return err};continue}
  if err=os.MkdirAll(filepath.Dir(target),0755);err!=nil{return err}
  input,e:=file.Open();if e!=nil{return e}
  output,e:=os.OpenFile(target,os.O_WRONLY|os.O_CREATE|os.O_TRUNC,0644);if e!=nil{input.Close();return e}
  _,e=io.Copy(output,input);input.Close();closeErr:=output.Close();if e!=nil{return e};if closeErr!=nil{return closeErr}
 }
 exe:=filepath.Join(root,"ConnWatch.exe")
 ps:=`$ErrorActionPreference='Stop';$root=`+quote(root)+`;$exe=`+quote(exe)+`;$ws=New-Object -ComObject WScript.Shell;foreach($folder in @([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('Programs'))){$lnk=$ws.CreateShortcut((Join-Path $folder 'ConnWatch Network.lnk'));$lnk.TargetPath=$exe;$lnk.WorkingDirectory=$root;$lnk.IconLocation=$exe;$lnk.Save()};$key='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ConnWatchNetwork';New-Item -Path $key -Force|Out-Null;(@{DisplayName='ConnWatch Network';DisplayVersion='3.0.0';Publisher='ZakirUllah';InstallLocation=$root;DisplayIcon=$exe;UninstallString=('powershell.exe -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $root 'Uninstall.ps1')+'"')}).GetEnumerator()|ForEach-Object {New-ItemProperty -Path $key -Name $_.Key -Value $_.Value -PropertyType String -Force|Out-Null}`
 // No shell handles app paths; PowerShell string values are single-quote escaped above.
 command:=exec.Command("powershell.exe","-NoProfile","-NonInteractive","-Command",ps)
 command.SysProcAttr=&syscall.SysProcAttr{HideWindow:true,CreationFlags:0x08000000}
 if output,err:=command.CombinedOutput();err!=nil{return fmt.Errorf("files installed, but shortcuts could not be created: %v\n%s",err,string(output))}
 if message("ConnWatch Network has been installed.\n\nUse the desktop shortcut to open the app.\n\nLaunch now?",0x24)==6{
  command:=exec.Command(exe);command.Dir=root;if err=command.Start();err!=nil{return err}
 }
 return nil
}
func main(){if err:=install();err!=nil{message("Installation could not finish.\n\n"+err.Error()+"\n\nClose ConnWatch if it is already running, then try again.",0x10)}}
