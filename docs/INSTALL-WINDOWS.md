# Windows installation

Developed by ZakirUllah · ConnWatch Network 3.0.0

## Windows binary availability

The installer and portable ZIP were supplied separately. Their GitHub binary upload is pending. The source edition below is available in this repository.

## Setup edition

1. Download `ConnWatch-Network-Setup-3.0.0.exe` from [downloads](../downloads).
2. Close any earlier ConnWatch windows, including copies started from CMD.
3. Run the setup executable normally. Do not extract the EXE with an archive utility.
4. Complete the per-user installation and open the **ConnWatch Network** shortcut.
5. Select the correct adapter and verify its displayed IP and subnet before starting a scan.

This package targets Windows 10/11 x64 and bundles Python/Qt. It is unsigned and is not claimed as native-Windows-verified. If Windows blocks it, follow your organization's app approval process or inspect/run the source using a trusted Python installation. Disabling Windows protection is not a setup requirement.

## Portable edition

1. Download `ConnWatch-Network-Windows-3.0.0.zip`.
2. Right-click the ZIP, choose **Extract All**, and select a new empty folder.
3. Open the extracted folder and double-click `ConnWatch.exe`.
4. Keep the distributed `runtime`, `application`, notices and documentation alongside the EXE.

Do not run the EXE from inside the compressed ZIP. Portable describes how application files are distributed; user records still use the default per-user workspace unless `--data-dir` is selected.

## Run editable source

Install a trusted Python 3.10+ x64 distribution, open CMD in the folder containing `main.py`, and run:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
```

Later launches only need the final command. Keep the terminal open when diagnosing an error.

## First network assessment

1. Select the adapter attached to the network you intend to assess.
2. Check the detected subnet. Large adapter ranges require a smaller permitted range.
3. Choose **Discovery** for a light initial run or **Standard** for selected common services.
4. Click **Scan network** and review progress.
5. Inspect Devices, add notes and export the completed assessment.
6. Repeat the same scope later to compare observations.

## Startup diagnostics

From the fully extracted portable folder:

```bat
runtime\python.exe -X faulthandler application\main.py
runtime\python.exe application\main.py --self-check
```

The self-check sends zero scan probes. Check `connwatch.log`, `startup-trace.log` and `launcher-startup.log` under `%LOCALAPPDATA%\ZakirUllah\ConnWatchDesktop`. Close the existing ConnWatch copy before launching again. To test a separate workspace without deleting records:

```bat
runtime\python.exe application\main.py --data-dir "%LOCALAPPDATA%\ConnWatch-Network-Check"
```

## Check download integrity

Open PowerShell in the download folder:

```powershell
Get-FileHash .\ConnWatch-Network-Setup-3.0.0.exe -Algorithm SHA256
Get-FileHash .\ConnWatch-Network-Windows-3.0.0.zip -Algorithm SHA256
```

Compare the output with [SHA256SUMS.txt](../downloads/SHA256SUMS.txt). A matching hash confirms bytes match the published manifest; it is not a trusted publisher signature.

## Uninstall and records

Use the installed uninstall entry or supplied uninstall mechanism. Back up your workspace first if you need to retain evidence. Do not delete the database or lock files to resolve a running-instance warning. See [troubleshooting](TROUBLESHOOTING.md).
