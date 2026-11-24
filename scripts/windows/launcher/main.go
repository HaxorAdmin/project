//go:build windows
package main

import (
 "fmt"
 "time"
 "os"
 "os/exec"
 "path/filepath"
 "syscall"
 "unsafe"
)
var user32 = syscall.NewLazyDLL("user32.dll")
var messageBox = user32.NewProc("MessageBoxW")
func alert(text string) {
 title,_:=syscall.UTF16PtrFromString("ConnWatch Network")
 body,_:=syscall.UTF16PtrFromString(text)
 messageBox.Call(0,uintptr(unsafe.Pointer(body)),uintptr(unsafe.Pointer(title)),0x10)
}
func main(){
 exe,err:=os.Executable();if err!=nil{alert(err.Error());return}
 root:=filepath.Dir(exe)
 runtime:=filepath.Join(root,"runtime","pythonw.exe")
 entry:=filepath.Join(root,"application","main.py")
 for _,file:=range []string{runtime,entry}{if _,err=os.Stat(file);err!=nil{alert("The application folder is incomplete. Extract the full ZIP or reinstall ConnWatch.\n\nMissing: "+file);return}}
 args:=append([]string{entry},os.Args[1:]...)
 cmd:=exec.Command(runtime,args...);cmd.Dir=filepath.Join(root,"application")
 cmd.SysProcAttr=&syscall.SysProcAttr{HideWindow:true,CreationFlags:0x08000000}
 cmd.Env=append(os.Environ(),"QT_PLUGIN_PATH="+filepath.Join(root,"runtime","Lib","site-packages","PySide6","plugins"))
 logDir:=filepath.Join(os.Getenv("LOCALAPPDATA"),"ZakirUllah","ConnWatchDesktop")
 os.MkdirAll(logDir,0755)
 logPath:=filepath.Join(logDir,"launcher-startup.log")
 logFile,logErr:=os.OpenFile(logPath,os.O_CREATE|os.O_TRUNC|os.O_WRONLY,0644)
 if logErr==nil{defer logFile.Close();fmt.Fprintln(logFile,time.Now().Format(time.RFC3339),"Launching bundled network application");cmd.Stdout=logFile;cmd.Stderr=logFile}
 if err=cmd.Run();err!=nil{alert(fmt.Sprintf("ConnWatch could not start or closed with an error.\n\n%v\n\nCheck connwatch.log and launcher-startup.log in your local app-data ZakirUllah/ConnWatchDesktop folder. Keep all runtime files together.",err))}
}
