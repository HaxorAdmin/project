# Kali/Linux GUI setup

Developed by ZakirUllah · ConnWatch Network 3.0.0

A graphical desktop, Python 3.10+ and network access for the first dependency install are required. This is a Qt desktop application.

## 1. Get the source

```bash
git clone https://github.com/HaxorAdmin/project.git
cd project
```

For this private repository, sign in using your normal Git credential setup or download **Code → Download ZIP** from GitHub while signed in. Extract and enter the folder containing `main.py`.

If you use the release source ZIP, extract it and enter its `ConnWatch-Network` folder instead.

## 2. Install missing system prerequisites

On Kali/Debian, install these only if your system does not already provide them:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip libxcb-cursor0
```

Use your normal account for the application. Administrator/root access is not a default launch requirement.

## 3. Create an isolated environment

Run from the directory containing `requirements.txt`:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Keep the `.venv` folder beside the source. Do not install these dependencies into Kali's system Python using `--break-system-packages`.

## 4. Open the GUI

```bash
.venv/bin/python main.py
```

Select the intended adapter, confirm its detected IP/subnet and click **Scan network**. Review Devices and Scan history, then export a report if needed.

## 5. Open it again later

```bash
cd /path/to/project
.venv/bin/python main.py
```

Replace `/path/to/project` with your real extracted/cloned folder. You can also run:

```bash
sh Start-Kali.sh
```

## Kali in VirtualBox or VMware

The app sees the network attached to the Kali VM. NAT commonly exposes a virtual subnet; host-only mode exposes the lab network. To assess an authorized physical LAN, configure the VM adapter for an appropriate bridged connection. Guest Wi-Fi bridging and client isolation can limit discovery. The tool cannot automatically see all networks attached to the Windows host.

Check the guest interface locally with:

```bash
ip -4 addr
ip route
```

Match the selected adapter and scope in ConnWatch. Public IP ranges and IPv6 subnet sweeps are not supported. Unknown or blocked devices may not respond.

## Diagnose without scanning

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python main.py --data-dir /tmp/connwatch-check --self-check
QT_QPA_PLATFORM=offscreen .venv/bin/python -m unittest discover -s tests -v
```

Offscreen mode is for diagnostics/tests. Launch normally for an interactive window. If Qt reports missing xcb libraries, install the exact missing system dependency reported in its message. See [troubleshooting](TROUBLESHOOTING.md).

## Download checksums

Download all files named in the manifest into the same folder, then run:

```bash
sha256sum --ignore-missing -c SHA256SUMS.txt
```

Missing files will report an error; a matching checksum is an integrity comparison, not a publisher signature.
