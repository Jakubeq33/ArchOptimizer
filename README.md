# ⚡ Arch Optimizer (WebView)

A lightweight Windows optimization app built with **Python + pywebview**.  
Get a clear **Computer Health** dashboard, kill heavy tasks, deep-clean disk & browsers, and hunt down common slow-down apps — all in one place.

> 🪟 Windows 10/11 • 🐍 Python • 🧩 psutil/pywebview • (optional) GPUtil

---

## ✨ Features

- 🧠 **Computer Health** — live CPU / RAM / Swap / Disk / Temps / Battery / GPU
- 🔪 **Task-Killer** — list non-system processes and kill selected ones fast
- 🧹 **Disk-Cleaner+**
  - Downloads, Recycle Bin (native `SHEmptyRecycleBinW`), user Temp, large files (≥100 MB)
  - **Browser cleanup**: Cache (Code/GPU/Media/Service Worker/Shader/D3D) & Cookies per profile  
    Supports **Chrome / Edge / Brave / Vivaldi / Opera / Opera GX / Firefox**  
    Optional **Force-close** to unlock files
- 🐢 **Slowless Cleaner**
  - Detects typical performance killers: overlays (Discord/Steam/Xbox/NVIDIA/Overwolf), cloud sync (OneDrive/Dropbox/Drive/Mega), launchers (Steam/Epic/Battle.net/Riot/Ubi/EA), RGB tools, updaters
  - **Startup manager** — list & disable HKCU/HKLM `Run/RunOnce` and Startup folder entries

---

## 🚀 Quick Start

```bash
# Python 3.10+ recommended
pip install -r requirements.txt   # psutil, pywebview, (optional) gputil, pywin32 on Windows
python app.py
