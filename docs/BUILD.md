# Rebuilding the Windows release

Normal users should run the packaged setup executable. This page is for source review and release engineering.

Inputs used for this release: Go 1.27.4, official CPython 3.12.10 Windows x64 embeddable ZIP, PySide6-Essentials / shiboken6 6.8.3 and psutil 7.2.2 Windows wheels. Python build helper dependencies are `pefile` and, for the optional presentation, `reportlab` and Pillow. The Go launcher and installer use the standard library. Icons/manifests were compiled with `github.com/akavel/rsrc` v0.10.2.

1. Run `python scripts/fetch_windows_runtime.py` to obtain the pinned runtime inputs.
2. Install a real Go toolchain. From `scripts/windows/launcher`, generate `rsrc.syso` with rsrc from the provided icon/manifest and compile with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w -H windowsgui" -o ../../../build/ConnWatch.exe .` on a Unix build host. On Windows set the environment variables using your shell's syntax. Paths are relative to that launcher directory.
3. Run `python scripts/build_windows.py` from the project. It packages the app, official runtime, recursively resolved shipped DLL dependencies, notices, documentation and editable source. The manifest and portable ZIP are generated in `build/`.
4. Copy `build/windows-payload.zip` to `scripts/windows/setup/payload.zip`, generate that package's icon/manifest resource, and compile the setup package with the same Go Windows build flags. The embedded ZIP becomes the installer's payload. Do not distribute build input caches or this duplicate embedded-payload file with the source archive.
5. Test the complete package on native Windows 10/11 x64 before calling it a Windows-verified release. Test first install, normal launch, process attribution, rule changes, exports, second launch, shortcuts, elevated launch and uninstall. Code signing is a separate release step and has not been performed.

The Qt runtime remains dynamically loaded and replaceable; see the included third-party notices. Keeping its original directory structure is necessary for plugin and DLL lookup. The launcher deliberately opens the bundled Python runtime without a console window; it is not a system-Python installer.

Release 3.0 also bundles the editable offline manufacturer-prefix snapshot and its attribution. The entry point is now `app/network_window.py` through `main.py`. Use the network acceptance checklist in this folder; source tests include retained workstation regression tests.
