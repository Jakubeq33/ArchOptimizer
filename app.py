import os, platform, psutil, json, threading, time, shutil, tempfile, ctypes, fnmatch, re
from pathlib import Path
import webview

IS_WINDOWS = platform.system().lower().startswith("win")
if IS_WINDOWS:
    import winreg

try:
    import GPUtil 
    HAS_GPU = True
except Exception:
    GPUtil = None
    HAS_GPU = False

APP_DIR = Path(__file__).parent.resolve()
USER_FILE = APP_DIR / "user.json"

LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA") or "").expanduser()
APPDATA      = Path(os.environ.get("APPDATA") or "").expanduser()
PROGRAMDATA  = Path(os.environ.get("PROGRAMDATA") or "").expanduser()

WINDOWS_SYSTEM_NAMES = {
    "system idle process","system","registry","smss.exe","csrss.exe","wininit.exe",
    "services.exe","lsass.exe","winlogon.exe","fontdrvhost.exe","dwm.exe","sihost.exe","ctfmon.exe"
}

def is_system_process(p: psutil.Process) -> bool:
    try:
        if p.pid <= 4: return True
        name = (p.name() or "").lower()
        if name in WINDOWS_SYSTEM_NAMES: return True
        if IS_WINDOWS:
            try:
                owner = (p.username() or "").lower()
            except Exception:
                owner = ""
            if any(s in owner for s in ["nt authority\\system","system","local service","network service"]):
                return True
            try:
                exe = (p.exe() or "").lower()
                windir = (os.environ.get("WINDIR") or "c:\\windows").lower()
                if exe.startswith(windir): return True
            except Exception:
                pass
    except Exception:
        return True
    return False

def proc_to_dict(p: psutil.Process):
    d = {"pid": p.pid, "name": "", "cpu": 0.0, "memory_mb": 0.0, "status": "", "exe": "", "user": ""}
    try:
        d["name"] = p.name()
        d["cpu"] = p.cpu_percent(interval=0.0)
        d["memory_mb"] = round((p.memory_info().rss)/1024/1024, 2)
        d["status"] = p.status()
        d["user"] = p.username()
        try: d["exe"] = p.exe()
        except Exception: pass
    except Exception: pass
    return d

def bytes_to_gb(b): return round(b / (1024**3), 2)

def fmt_size(num_bytes: int) -> str:
    if num_bytes is None: return "?"
    units = ['B','KB','MB','GB','TB']
    size = float(num_bytes)
    for u in units:
        if size < 1024.0:
            return f"{size:.1f} {u}"
        size /= 1024.0
    return f"{size:.1f} PB"

def dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for f in files:
            try:
                fp = Path(root)/f
                total += fp.stat().st_size
            except Exception:
                pass
    return total

def safe_remove(p: Path):
    try:
        if p.is_symlink() or p.is_file():
            size = p.stat().st_size if p.exists() and p.is_file() else 0
            p.unlink(missing_ok=True)
        elif p.is_dir():
            size = dir_size(p)
            shutil.rmtree(p, ignore_errors=True)
        else:
            size = 0
        return True, None, size
    except Exception as e:
        return False, str(e), 0

def empty_recycle_bin():
    if not IS_WINDOWS:
        return False, "unsupported_os"
    try:
        SHERB_NOCONFIRMATION = 0x00000001
        SHERB_NOPROGRESSUI   = 0x00000002
        SHERB_NOSOUND        = 0x00000004
        ctypes.windll.shell32.SHEmptyRecycleBinW(
            None, None,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
        )
        return True, None
    except Exception as e:
        return False, str(e)

def home_dir() -> Path:
    return Path.home()

def downloads_dir() -> Path:
    return home_dir() / "Downloads"

def user_temp_dirs() -> list[Path]:
    s = set()
    import tempfile as _tf
    s.add(Path(_tf.gettempdir()))
    for env in ("TEMP","TMP"):
        v = os.environ.get(env)
        if v: s.add(Path(v))
    return [p for p in s if p.exists()]

def big_files_scan(threshold_bytes: int = 100*1024*1024, limit: int = 50):
    base = home_dir()
    excluded = {
        str(home_dir() / "AppData"),
        str(home_dir() / ".cache"),
        str(home_dir() / ".local"),
    }
    found = []
    for root, dirs, files in os.walk(base, onerror=lambda e: None):
        if any(str(root).startswith(ex) for ex in excluded):
            continue
        for f in files:
            try:
                fp = Path(root)/f
                st = fp.stat()
                if st.st_size >= threshold_bytes:
                    found.append((fp, st.st_size))
            except Exception:
                pass
            if len(found) > 2000:
                break
    found.sort(key=lambda t: t[1], reverse=True)
    return found[:limit]

def chromium_roots():
    roots = []
    if LOCALAPPDATA:
        roots.append(("chrome", LOCALAPPDATA / "Google" / "Chrome" / "User Data"))
        roots.append(("edge", LOCALAPPDATA / "Microsoft" / "Edge" / "User Data"))
        roots.append(("brave", LOCALAPPDATA / "BraveSoftware" / "Brave-Browser" / "User Data"))
        roots.append(("vivaldi", LOCALAPPDATA / "Vivaldi" / "User Data"))
        roots.append(("opera", LOCALAPPDATA / "Opera Software" / "Opera Stable"))
        roots.append(("operagx", LOCALAPPDATA / "Opera Software" / "Opera GX Stable"))
    return roots

def firefox_profiles():
    profiles = []
    base = APPDATA / "Mozilla" / "Firefox" / "Profiles"
    if base.exists():
        for p in base.iterdir():
            if p.is_dir():
                profiles.append(("firefox", p))
    return profiles

CHROMIUM_CACHE_DIRS = [
    "Cache", "Code Cache", "GPUCache", "Media Cache", "ShaderCache",
    "GrShaderCache", "Service Worker\\CacheStorage", "DawnCache", "D3DCache"
]
CHROMIUM_COOKIE_PATH = Path("Network") / "Cookies"
FIREFOX_CACHE_DIRS = ["cache2", "startupCache", "OfflineCache"]
FIREFOX_COOKIE_FILE = "cookies.sqlite"

def find_chromium_profiles(root: Path):
    if not root.exists():
        return []
    profiles = []
    if (root / "Network").exists() or (root / "Cache").exists():
        profiles.append(root)
    for p in root.iterdir():
        try:
            if p.is_dir() and p.name.lower().startswith("profile"):
                profiles.append(p)
        except Exception:
            pass
    if (root / "Default").exists():
        profiles.append(root / "Default")
    uniq = []
    seen = set()
    for p in profiles:
        sp = str(p)
        if sp not in seen:
            seen.add(sp); uniq.append(p)
    return uniq

def size_of_chromium_cache(profile_dir: Path) -> int:
    return sum(dir_size(profile_dir / rel) for rel in CHROMIUM_CACHE_DIRS)

def chromium_cookie_file(profile_dir: Path) -> Path:
    return (profile_dir / CHROMIUM_COOKIE_PATH)

def size_of_firefox_cache(profile_dir: Path) -> int:
    return sum(dir_size(profile_dir / rel) for rel in FIREFOX_CACHE_DIRS)

def firefox_cookie_path(profile_dir: Path) -> Path:
    return profile_dir / FIREFOX_COOKIE_FILE

def kill_browsers():
    names = {"chrome.exe","msedge.exe","brave.exe","vivaldi.exe","opera.exe","opera_gx.exe","firefox.exe"}
    killed = 0
    for p in psutil.process_iter(["pid","name"]):
        try:
            if (p.info.get("name") or "").lower() in names:
                p.terminate()
                killed += 1
        except Exception:
            pass
    return killed

SLOW_CATALOG = [
    ("Discord", ["discord", "discordoverlayhost"], "Nakładka / komunikator"),
    ("Steam Overlay", ["steamwebhelper","GameOverlayUI"], "Nakładka Steam"),
    ("Xbox Game Bar", ["gamebar","xboxgamebar"], "Nakładka Xbox/GameDVR"),
    ("NVIDIA Overlay", ["nvidia share","nvcontainer","nvtoplevel"], "Nakładka GeForce Experience"),
    ("Overwolf", ["overwolf"], "Nakładki Overwolf"),

    ("OneDrive", ["onedrive"], "Synchronizacja w tle"),
    ("Dropbox", ["dropbox"], "Synchronizacja w tle"),
    ("Google Drive", ["googledrive","google drive"], "Synchronizacja w tle"),
    ("Mega", ["megasync"], "Synchronizacja w tle"),

    ("Steam", ["steam.exe","steamservice","steamwebhelper"], "Launcher/sklep"),
    ("Epic Games", ["epicgameslauncher"], "Launcher/sklep"),
    ("Battle.net", ["battlenet","agent.exe"], "Launcher/sklep"),
    ("Riot", ["riotclient","riotclientservices"], "Launcher/sklep"),
    ("Ubisoft Connect", ["upc.exe","upc"], "Launcher/sklep"),
    ("EA App", ["eadesktop","origin"], "Launcher/sklep"),

    ("Razer Synapse", ["rzsynapse","rzceef"], "RGB/daemon"),
    ("Logitech G Hub", ["lghub","lghub_agent","lghub_updater"], "RGB/daemon"),
    ("Corsair iCUE", ["icue"], "RGB/daemon"),
    ("MSI Dragon Center", ["dragoncenter","apmsvc"], "Narzędzia OEM"),
    ("ASUS Armoury Crate", ["armourycrate","asussci","acpower"], "Narzędzia OEM"),
    ("NZXT CAM", ["nzxtcam"], "Monitoring/daemon"),
    ("MSI Afterburner", ["msiafterburner"], "OC/monitoring"),

    ("Adobe Updater", ["adobeupdater","armsvc"], "Updater"),
    ("Google Updater", ["googleupdate","googledrivesync"], "Updater"),
    ("Teams", ["teams"], "Komunikator w tle"),
    ("Zoom", ["zoom"], "Komunikator w tle"),
]

def _match_catalog(name: str, exe: str):
    nm = (name or "").lower()
    ex = (exe or "").lower()
    for label, needles, note in SLOW_CATALOG:
        for nd in needles:
            if nd in nm or (ex and nd in ex):
                return label, note
    return None, None

STARTUP_SCOPES = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]
STARTUP_FOLDERS = []
if IS_WINDOWS:
    STARTUP_FOLDERS = [
        APPDATA / r"Microsoft\Windows\Start Menu\Programs\Startup",
        PROGRAMDATA / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]

CMD_EXE_RE = re.compile(r'^"?([^"]+?\.exe)"?(?:\s|$)', re.IGNORECASE)

def extract_exe_from_cmd(cmd: str) -> str:
    if not cmd: return ""
    m = CMD_EXE_RE.match(cmd.strip())
    if m: return m.group(1)
    return cmd.split(" ")[0].strip('"')

def read_startup_registry():
    entries = []
    if not IS_WINDOWS: return entries
    for scope, subkey in STARTUP_SCOPES:
        hk = winreg.HKEY_CURRENT_USER if scope=="HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hk, subkey) as k:
                i = 0
                while True:
                    try:
                        name, val, _t = winreg.EnumValue(k, i)
                        i += 1
                        exe = extract_exe_from_cmd(str(val))
                        entries.append({
                            "type":"registry","scope":scope,"subkey":subkey,
                            "name":name,"command":str(val),"exe":exe
                        })
                    except OSError:
                        break
        except OSError:
            continue
    return entries

def read_startup_folders():
    entries = []
    for folder in STARTUP_FOLDERS:
        if folder and folder.exists():
            for p in folder.iterdir():
                if p.suffix.lower() in {".lnk",".url",".bat",".cmd",".exe"}:
                    entries.append({
                        "type":"folder","folder":str(folder),
                        "name":p.name, "path":str(p)
                    })
    return entries

def disable_startup_entry(entry: dict):
    try:
        if entry.get("type") == "registry" and IS_WINDOWS:
            scope = entry.get("scope")
            subkey = entry.get("subkey")
            name  = entry.get("name")
            hk = winreg.HKEY_CURRENT_USER if scope=="HKCU" else winreg.HKEY_LOCAL_MACHINE
            try:
                with winreg.OpenKey(hk, subkey, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, name)
                    return True, None
            except PermissionError as e:
                return False, "need_admin"
            except FileNotFoundError:
                return False, "not_found"
            except OSError as e:
                return False, str(e)
        elif entry.get("type") == "folder":
            p = Path(entry.get("path",""))
            if p.exists():
                try:
                    p.unlink()
                    return True, None
                except PermissionError:
                    return False, "access_denied"
                except OSError as e:
                    return False, str(e)
            return False, "not_found"
    except Exception as e:
        return False, str(e)
    return False, "unsupported"

class ArchOptymalizerAPI:

    def __init__(self):
        self.system_info = {}
        self.running = True
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def get_user(self):
        try:
            if USER_FILE.exists():
                return json.loads(USER_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def save_user(self, user):
        try:
            USER_FILE.write_text(json.dumps(user, ensure_ascii=False, indent=2), encoding="utf-8")
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "reason": str(e)}

    def login(self, email, password, remember=False):
        u = self.get_user()
        if not u:
            return {"ok": False, "reason": "no_user"}
        if (u.get("email", "").lower() == (email or "").lower()) and u.get("password") == password:
            try:
                u["remember"] = bool(remember)
                USER_FILE.write_text(json.dumps(u, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            return {"ok": True, "user": u}
        return {"ok": False, "reason": "invalid_credentials"}

    def _monitor_loop(self):
        while self.running:
            try:
                self.system_info = self._health_snapshot()
            except Exception:
                pass
            time.sleep(1)

    def _health_snapshot(self):
        cpu_total = psutil.cpu_percent(interval=None)
        cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)

        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        disk_partitions = []
        total_used = total_size = 0
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk_partitions.append({
                    "device": part.device,
                    "mount": part.mountpoint,
                    "used_gb": bytes_to_gb(usage.used),
                    "total_gb": bytes_to_gb(usage.total),
                    "percent": usage.percent
                })
                total_used += usage.used; total_size += usage.total
            except Exception:
                continue
        disk_total_percent = round((total_used/total_size)*100, 1) if total_size else 0.0

        temps = {}
        try:
            tmap = psutil.sensors_temperatures()
            for k, arr in tmap.items():
                if arr:
                    temps[k] = [{"label": it.label or k, "current": it.current} for it in arr if it.current is not None]
        except Exception:
            pass

        battery = {}
        try:
            bt = psutil.sensors_battery()
            if bt:
                battery = {"percent": round(bt.percent,1), "plugged": bool(bt.power_plugged)}
        except Exception:
            pass

        gpus = []
        if HAS_GPU:
            try:
                for g in GPUtil.getGPUs():
                    gpus.append({
                        "id": g.id,
                        "name": g.name,
                        "load_percent": round(g.load*100, 1),
                        "mem_used_gb": round(g.memoryUsed/1024, 2),
                        "mem_total_gb": round(g.memoryTotal/1024, 2),
                        "temp_c": g.temperature
                    })
            except Exception:
                pass

        return {
            "cpu": {"total_percent": cpu_total, "per_core": cpu_per_core},
            "ram": {"used_gb": bytes_to_gb(vm.used), "total_gb": bytes_to_gb(vm.total), "percent": vm.percent},
            "swap": {"used_gb": bytes_to_gb(sm.used), "total_gb": bytes_to_gb(sm.total), "percent": sm.percent},
            "disk": {"total_percent": disk_total_percent, "partitions": disk_partitions},
            "temps": temps,
            "battery": battery,
            "gpu": {"available": HAS_GPU and len(gpus)>0, "items": gpus},
            "meta": {"system": platform.system(), "cpu_name": platform.processor()}
        }

    def get_health(self):
        return self._health_snapshot()

    def list_processes(self):
        procs = []
        snap = []
        for p in psutil.process_iter():
            try:
                if is_system_process(p): continue
                _ = p.cpu_percent(interval=0.0)
                snap.append(p)
            except Exception: pass
        psutil.cpu_percent(interval=0.2)
        for p in snap:
            try: procs.append(proc_to_dict(p))
            except Exception: pass
        procs.sort(key=lambda x: (x["cpu"], x["memory_mb"]), reverse=True)
        return {"items": procs, "count": len(procs)}

    def kill_processes(self, pids):
        results = []
        for pid in pids or []:
            try:
                p = psutil.Process(int(pid))
                if is_system_process(p):
                    results.append({"pid": pid, "ok": False, "reason": "system_or_protected"})
                    continue
                p.terminate()
                results.append({"pid": pid, "ok": True})
            except psutil.AccessDenied:
                results.append({"pid": pid, "ok": False, "reason": "access_denied"})
            except psutil.NoSuchProcess:
                results.append({"pid": pid, "ok": False, "reason": "no_such_process"})
            except Exception as e:
                results.append({"pid": pid, "ok": False, "reason": str(e)})
        return {"results": results}

    def scan_cleanup(self, options: dict):
        opts = options or {}
        out = {"totals": {}, "lists": {"big_top": [], "browsers": []}}

        if opts.get("downloads"):
            d = downloads_dir()
            out["totals"]["downloads_bytes"] = dir_size(d)

        if opts.get("temp"):
            total = 0
            for tdir in user_temp_dirs():
                total += dir_size(tdir)
            out["totals"]["temp_bytes"] = total

        if opts.get("recycle"):
            out["totals"]["recycle_bytes"] = None  # size niełatwo dostępny

        if opts.get("big"):
            big = big_files_scan()
            out["lists"]["big_top"] = [{"path": str(p), "bytes": s, "size": fmt_size(s)} for p,s in big]
            out["totals"]["big_bytes"] = sum(s for _,s in big)

        b_cache = b_cookies = 0
        if opts.get("browser_cache") or opts.get("browser_cookies"):
            for name, root in chromium_roots():
                profs = find_chromium_profiles(root)
                for prof in profs:
                    entry = {"browser": name, "profile": str(prof), "cache_bytes": 0, "cookie_bytes": 0, "cookie_path": None}
                    if opts.get("browser_cache"):
                        cb = size_of_chromium_cache(prof)
                        entry["cache_bytes"] = cb; b_cache += cb
                    if opts.get("browser_cookies"):
                        cpath = chromium_cookie_file(prof)
                        entry["cookie_path"] = str(cpath)
                        try:
                            if cpath.exists():
                                sz = cpath.stat().st_size
                                entry["cookie_bytes"] = sz; b_cookies += sz
                        except Exception:
                            pass
                    out["lists"]["browsers"].append(entry)
            for name, prof in firefox_profiles():
                entry = {"browser": name, "profile": str(prof), "cache_bytes": 0, "cookie_bytes": 0, "cookie_path": None}
                if opts.get("browser_cache"):
                    fb = size_of_firefox_cache(prof)
                    entry["cache_bytes"] = fb; b_cache += fb
                if opts.get("browser_cookies"):
                    cpath = firefox_cookie_path(prof)
                    entry["cookie_path"] = str(cpath)
                    try:
                        if cpath.exists():
                            sz = cpath.stat().st_size
                            entry["cookie_bytes"] = sz; b_cookies += sz
                    except Exception:
                        pass
                out["lists"]["browsers"].append(entry)

            out["totals"]["browsers_cache_bytes"] = b_cache
            out["totals"]["browsers_cookie_bytes"] = b_cookies

        out["totals"]["sum_known_bytes"] = sum(v for v in out["totals"].values() if isinstance(v, (int, float)))
        return out

    def run_cleanup(self, options: dict):
        opts = options or {}
        freed = 0
        actions = []

        if opts.get("browser_force_close"):
            killed = kill_browsers()
            actions.append({"category":"browser", "path":"<all>", "ok": True, "info": f"killed:{killed}"})

        if opts.get("downloads"):
            d = downloads_dir()
            if d.exists():
                for p in d.iterdir():
                    ok, err, size = safe_remove(p)
                    actions.append({"category":"downloads", "path": str(p), "ok": ok, "error": err})
                    if ok: freed += size

        if opts.get("temp"):
            for tdir in user_temp_dirs():
                for p in tdir.iterdir():
                    ok, err, size = safe_remove(p)
                    actions.append({"category":"temp", "path": str(p), "ok": ok, "error": err})
                    if ok: freed += size

        if opts.get("recycle"):
            ok, err = empty_recycle_bin()
            actions.append({"category":"recycle", "path":"<recycle-bin>", "ok": ok, "error": err})

        if opts.get("big"):
            for p, s in big_files_scan():
                ok, err, _ = safe_remove(p)
                actions.append({"category":"big", "path": str(p), "ok": ok, "error": err})
                if ok: freed += s

        if opts.get("browser_cache"):
            for name, root in chromium_roots():
                for prof in find_chromium_profiles(root):
                    for rel in CHROMIUM_CACHE_DIRS:
                        p = prof / rel
                        if p.exists():
                            size_before = dir_size(p)
                            ok, err, _ = safe_remove(p)
                            actions.append({"category":f"browser_cache:{name}", "path": str(p), "ok": ok, "error": err})
                            if ok: freed += size_before
            for _, prof in firefox_profiles():
                for rel in FIREFOX_CACHE_DIRS:
                    p = prof / rel
                    if p.exists():
                        size_before = dir_size(p)
                        ok, err, _ = safe_remove(p)
                        actions.append({"category":"browser_cache:firefox", "path": str(p), "ok": ok, "error": err})
                        if ok: freed += size_before

        if opts.get("browser_cookies"):
            for name, root in chromium_roots():
                for prof in find_chromium_profiles(root):
                    cpath = chromium_cookie_file(prof)
                    if cpath.exists():
                        try: sz = cpath.stat().st_size
                        except Exception: sz = 0
                        ok, err, _ = safe_remove(cpath)
                        actions.append({"category":f"browser_cookies:{name}", "path": str(cpath), "ok": ok, "error": err})
                        if ok: freed += sz
            for _, prof in firefox_profiles():
                cpath = firefox_cookie_path(prof)
                if cpath.exists():
                    try: sz = cpath.stat().st_size
                    except Exception: sz = 0
                    ok, err, _ = safe_remove(cpath)
                    actions.append({"category":"browser_cookies:firefox", "path": str(cpath), "ok": ok, "error": err})
                    if ok: freed += sz

        return {
            "ok": True,
            "freed_bytes": freed,
            "freed_human": fmt_size(freed),
            "actions_sample": actions[:250]
        }

    def scan_slowless(self, include_startup=True):
        running = []
        for p in psutil.process_iter():
            try:
                if is_system_process(p): continue
                info = proc_to_dict(p)
                label, note = _match_catalog(info["name"], info.get("exe",""))
                if label:
                    info["label"] = label
                    info["reason"] = note
                    running.append(info)
            except Exception:
                continue
        running.sort(key=lambda x: (x.get("cpu",0.0), x.get("memory_mb",0.0)), reverse=True)

        startup = []
        if include_startup:
            startup.extend(read_startup_registry())
            startup.extend(read_startup_folders())
            for it in startup:
                exe = (it.get("exe") or it.get("path") or it.get("command") or "")
                label, note = _match_catalog(Path(exe).name, exe)
                it["label"] = label or "Autostart"
                it["reason"] = note or ("Wpis autostartu" if it["type"]=="registry" else "Skrót w Startup")
        return {"running": running, "startup": startup}

    def disable_startup_batch(self, entries):
        results = []
        for e in entries or []:
            ok, err = disable_startup_entry(e)
            results.append({
                "target": e.get("name") or e.get("path"),
                "type": e.get("type"),
                "scope": e.get("scope"),
                "ok": ok, "error": err
            })
        return {"results": results}

def main():
    html = str((APP_DIR / 'index.html').resolve())
    api = ArchOptymalizerAPI()
    window = webview.create_window(
        'Arch Optimizer (WebView)',
        html,
        js_api=api,
        width=1100, height=760, min_size=(800, 560),
        background_color='#0b0b0c'
    )
    webview.start(debug=True)

if __name__ == "__main__":
    main()
