"""
Scanova : numériser simplement, quelle que soit la marque du scanner.

Installation :
    pip install customtkinter pillow requests zeroconf
    (Windows)  pip install pywin32
    (Linux)    pip install python-sane

Lancement :
    python scanova.py
"""
import io
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox

import customtkinter as ctk

# customtkinter dessine ses coins arrondis avec une police spéciale sous Windows. Quand Windows
# applique sa transparence (Mica / acrylique), le lissage de cette police laisse de petits carrés
# plus sombres dans chaque coin. On force donc le dessin par polygones, sans aucune police.
try:
    from customtkinter.windows.widgets.core_rendering import DrawEngine
    DrawEngine.preferred_drawing_method = "polygon_shapes"
except Exception:
    pass
import requests
from PIL import Image

requests.packages.urllib3.disable_warnings()
SYSTEM = platform.system()
CONFIG = os.path.join(os.path.expanduser("~"), ".scanova.json")

# ----------------------------------------------------------------------------
# Scanners : trois méthodes, toutes indépendantes de la marque
#   1. eSCL / AirScan : scanners et imprimantes multifonctions en Wi-Fi / réseau
#   2. WIA            : scanners USB ou réseau déclarés dans Windows
#   3. SANE           : scanners USB sous Linux
# ----------------------------------------------------------------------------


@dataclass
class Scanner:
    name: str
    kind: str  # "escl", "wia", "sane"
    info: dict = field(default_factory=dict)

    @property
    def model(self):
        return self.name.split(" (")[0]


def _host(base):
    return urllib.parse.urlparse(base).hostname


def _local(tag):
    return tag.split("}")[-1]


def new_session():
    s = requests.Session()
    s.verify = False        # certificats auto-signés des imprimantes
    s.trust_env = False     # ignorer les proxys : on parle à un appareil du réseau local
    s.headers["Connection"] = "close"  # certains serveurs d'imprimantes gèrent mal le keep-alive
    return s


def _parse_caps(content):
    caps = {"name": "Scanner", "maxw": None, "maxh": None, "modes": set(), "dpis": [], "formats": set()}
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return caps
    for el in root.iter():
        if _local(el.tag) == "MakeAndModel" and el.text:
            caps["name"] = el.text.strip()
    platen = next((e for e in root.iter() if _local(e.tag) == "Platen"), root)
    dpis = set()
    for el in platen.iter():
        t, txt = _local(el.tag), (el.text or "").strip()
        if t == "MaxWidth" and caps["maxw"] is None and txt.isdigit():
            caps["maxw"] = int(txt)
        elif t == "MaxHeight" and caps["maxh"] is None and txt.isdigit():
            caps["maxh"] = int(txt)
        elif t == "ColorMode" and txt:
            caps["modes"].add(txt)
        elif t in ("DocumentFormat", "DocumentFormatExt") and txt:
            caps["formats"].add(txt)
        elif t == "DiscreteResolution":
            for c in el:
                if _local(c.tag) == "XResolution" and (c.text or "").strip().isdigit():
                    dpis.add(int(c.text.strip()))
    caps["dpis"] = sorted(dpis)
    return caps


def escl_caps(base, timeout=3.0, retries=2):
    """Interroge un scanner eSCL. Renvoie ses capacités, ou None s'il ne répond pas / n'est pas eSCL."""
    for _ in range(retries):
        try:
            r = new_session().get(base + "/ScannerCapabilities", timeout=timeout)
        except requests.RequestException:
            time.sleep(0.5)
            continue
        if r.status_code == 200 and b"ScannerCapabilities" in r.content:
            return _parse_caps(r.content)
        return None
    return None


def _tcp_open(host, port, timeout):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _open_ports(host, ports, timeout):
    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        return [p for p, ok in zip(ports, ex.map(lambda p: _tcp_open(host, p, timeout), ports)) if ok]


def probe_escl(host, timeout=3.0, quick=False):
    """Teste une adresse (IP ou IP:port) et renvoie un Scanner eSCL si elle répond.
    quick=True : on vérifie d'abord que le port est ouvert, pour ne pas attendre une adresse qui ne répond pas."""
    host = host.strip().replace("http://", "").replace("https://", "").strip("/")
    if ":" in host:
        h, p = host.rsplit(":", 1)
        combos = [("http", p), ("https", p)]
    else:
        h, combos = host, [("http", 80), ("https", 443), ("http", 8080)]
    if quick:
        opened = _open_ports(h, sorted({int(p) for _, p in combos}), 1.5)
        combos = [(s, p) for s, p in combos if int(p) in opened]
    for scheme, port in combos:
        base = f"{scheme}://{h}:{port}/eSCL"
        caps = escl_caps(base, timeout)
        if caps:
            return Scanner(f"{caps['name']} ({h})", "escl", {"base": base})
    return None


def discover_escl_mdns(timeout=4.0):
    from zeroconf import ServiceBrowser, Zeroconf
    found = {}
    zc = Zeroconf()

    class Listener:
        def add_service(self, zc_, type_, name):
            info = zc_.get_service_info(type_, name, timeout=2500)
            if not info or not info.parsed_addresses():
                return
            props = {k.decode(): v.decode(errors="ignore") for k, v in info.properties.items() if v}
            addrs = info.parsed_addresses()
            host = next((a for a in addrs if ":" not in a), f"[{addrs[0]}]")
            scheme = "https" if "uscans" in type_ else "http"
            rs = props.get("rs", "eSCL").strip("/")
            label = props.get("ty") or name.split(".")[0]
            found[name] = Scanner(f"{label} ({host})", "escl", {"base": f"{scheme}://{host}:{info.port}/{rs}"})

        def update_service(self, *a):
            pass

        def remove_service(self, *a):
            pass

    browsers = [ServiceBrowser(zc, t, Listener()) for t in ("_uscan._tcp.local.", "_uscans._tcp.local.")]
    time.sleep(timeout)
    for b in browsers:
        b.cancel()
    zc.close()
    return list(found.values())


def _local_prefixes():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    good = {".".join(ip.split(".")[:3]) for ip in ips if not ip.startswith(("127.", "169.254."))}
    return sorted(good)[:3]


def discover_escl_sweep():
    """Plan B : on teste chaque adresse du réseau local (utile quand la détection automatique échoue)."""
    def check(host):
        for scheme, port in (("http", 80), ("https", 443)):
            if _tcp_open(host, port, 0.9):
                base = f"{scheme}://{host}:{port}/eSCL"
                caps = escl_caps(base, timeout=3.0, retries=1)
                if caps:
                    return Scanner(f"{caps['name']} ({host})", "escl", {"base": base})
        return None

    hosts = [f"{p}.{i}" for p in _local_prefixes() for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=64) as ex:
        return [r for r in ex.map(check, hosts) if r]


def _com(fn):
    """Les appels WIA (COM) doivent initialiser COM dans le thread qui les utilise."""
    def wrapper(*args):
        import pythoncom
        pythoncom.CoInitialize()
        try:
            return fn(*args)
        finally:
            pythoncom.CoUninitialize()
    return wrapper


def _discover_wia():
    import win32com.client
    mgr = win32com.client.Dispatch("WIA.DeviceManager")
    out = []
    for i in range(1, mgr.DeviceInfos.Count + 1):
        d = mgr.DeviceInfos[i]
        if d.Type in (2, 3):  # appareils photo et caméras : ignorés
            continue
        out.append(Scanner(f"{d.Properties('Name').Value} (USB/Windows)", "wia", {"id": d.DeviceID}))
    return out


def discover_wia():
    return _com(_discover_wia)() if SYSTEM == "Windows" else []


def discover_sane():
    if SYSTEM != "Linux":
        return []
    import sane
    sane.init()
    return [Scanner(f"{d[1]} {d[2]}", "sane", {"dev": d[0]}) for d in sane.get_devices()]


# ----------------------------------------------------------------------------
# Mémoire : ~/.scanova.json
#   devices : les scanners déjà vus ou utilisés (le dernier utilisé est proposé en premier)
#   theme   : "system", "light" ou "dark"
# ----------------------------------------------------------------------------

MAX_DEVICES = 10
_cfg_lock = threading.Lock()


def _read_config():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_config():
    cfg = _read_config()
    devs = [d for d in cfg.get("devices", []) if isinstance(d, dict) and d.get("key")]
    keys = {d["key"] for d in devs}
    for ip in cfg.get("ips", []):  # ancien format : simple liste d'adresses
        if isinstance(ip, str) and f"escl:{ip}" not in keys:
            devs.append({"key": f"escl:{ip}", "kind": "escl", "host": ip, "name": ip, "model": ip,
                         "last_used": 0, "last_seen": 0})
    cfg["devices"] = devs
    return cfg


def update_config(fn):
    with _cfg_lock:
        cfg = load_config()
        fn(cfg)
        cfg.pop("ips", None)
        tmp = CONFIG + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=1)
            os.replace(tmp, CONFIG)
        except OSError:
            pass


def _trim(devs):
    return sorted(devs, key=lambda d: (d.get("last_used", 0), d.get("last_seen", 0)), reverse=True)[:MAX_DEVICES]


def scanner_key(sc):
    return f"escl:{_host(sc.info['base'])}" if sc.kind == "escl" else f"{sc.kind}:{sc.name}"


def remember_scanners(found):
    """Mémorise les scanners réseau trouvés (pour les retrouver directement la fois suivante)."""
    now = time.time()

    def upd(cfg):
        devs = {d["key"]: d for d in cfg["devices"]}
        for s in found:
            if s.kind != "escl":
                continue
            k = scanner_key(s)
            d = devs.setdefault(k, {"key": k, "last_used": 0})
            d.update(kind="escl", name=s.name, model=s.model, host=_host(s.info["base"]),
                     base=s.info["base"], last_seen=now)
        cfg["devices"] = _trim(devs.values())
    update_config(upd)


def remember_used(sc):
    """Appelé après une numérisation réussie : ce scanner devient le scanner habituel."""
    now = time.time()

    def upd(cfg):
        k = scanner_key(sc)
        d = next((x for x in cfg["devices"] if x["key"] == k), None)
        if d is None:
            d = {"key": k}
            cfg["devices"].append(d)
        d.update(kind=sc.kind, name=sc.name, model=sc.model, last_used=now, last_seen=now)
        if sc.kind == "escl":
            d.update(host=_host(sc.info["base"]), base=sc.info["base"])
        cfg["devices"] = _trim(cfg["devices"])
    update_config(upd)


def preferred(found):
    """Parmi les scanners trouvés, celui qu'on a utilisé le plus récemment (None si jamais utilisé)."""
    devs = load_config()["devices"]
    best, best_t = None, 0
    for s in found:
        k = scanner_key(s)
        for d in devs:
            t = d.get("last_used", 0)
            if t > best_t and (d["key"] == k or (d.get("kind") == s.kind and d.get("model") == s.model)):
                best, best_t = s, t
    return best


# ----------------------------------------------------------------------------
# Recherche : d'abord ce que l'ordinateur connaît déjà, ensuite seulement les alentours
# ----------------------------------------------------------------------------

_BAD_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def windows_printer_hosts():
    """Adresses des imprimantes réseau déjà ajoutées dans Windows (port TCP/IP standard)."""
    if SYSTEM != "Windows":
        return []
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
              "Get-Printer | ForEach-Object { $p=$_; "
              "$port=Get-PrinterPort -Name $p.PortName -ErrorAction SilentlyContinue; "
              "[pscustomobject]@{Port=$p.PortName;Host=$port.PrinterHostAddress} } | ConvertTo-Json -Compress")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)).stdout.strip()
        rows = json.loads(out) if out else []
    except Exception:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    hosts = []
    for r in rows:
        h = (r.get("Host") or "").strip()
        if not h:  # port nommé « IP_192.168.1.25 » ou « 192.168.1.25 »
            m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", r.get("Port") or "")
            h = m.group(0) if m else ""
        if h and ":" not in h and h.lower() not in _BAD_HOSTS and h not in hosts:
            hosts.append(h)
    return hosts


def probe_known(d):
    """Retrouve un scanner mémorisé (on essaie d'abord l'adresse exacte mémorisée)."""
    base = d.get("base")
    if base:
        p = urllib.parse.urlparse(base)
        port = p.port or (443 if p.scheme == "https" else 80)
        if p.hostname and _tcp_open(p.hostname, port, 1.5):
            caps = escl_caps(base, timeout=3.0, retries=2)
            if caps:
                return Scanner(f"{caps['name']} ({p.hostname})", "escl", {"base": base})
    return probe_escl(d["host"], quick=True) if d.get("host") else None


def _safe(fn, *args):
    try:
        res = fn(*args)
        return [res] if isinstance(res, Scanner) else (res or [])
    except Exception:
        return []


def _merge(results):
    """Supprime les doublons, met les scanners réseau en premier et les mémorise."""
    seen, out = set(), []
    for s in results:
        k = scanner_key(s)
        if k not in seen:
            seen.add(k)
            out.append(s)
    out.sort(key=lambda s: s.kind != "escl")
    remember_scanners(out)
    return out


def discover_quick():
    """Étape 1 (rapide) : scanners mémorisés, scanners déclarés dans Windows (WIA) et
    imprimantes réseau déjà ajoutées dans Windows."""
    devs = [d for d in load_config()["devices"] if d.get("kind") == "escl" and d.get("host")]
    known = {d["host"] for d in devs}
    with ThreadPoolExecutor(max_workers=12) as ex:
        wia, sane = ex.submit(_safe, discover_wia), ex.submit(_safe, discover_sane)
        win_hosts = ex.submit(_safe, windows_printer_hosts)
        jobs = [ex.submit(_safe, probe_known, d) for d in devs]
        jobs += [ex.submit(_safe, probe_escl, h, 3.0, True) for h in win_hosts.result() if h not in known]
        results = [s for j in jobs for s in j.result()] + wia.result() + sane.result()
    return _merge(results)


def discover_wide():
    """Étape 2 : on cherche autour de soi (annonces réseau + balayage du réseau local)."""
    with ThreadPoolExecutor(max_workers=2) as ex:
        jobs = [ex.submit(_safe, discover_escl_mdns), ex.submit(_safe, discover_escl_sweep)]
        return _merge([s for j in jobs for s in j.result()])


def discover_all():
    """Tout en même temps (bouton « Rechercher »)."""
    with ThreadPoolExecutor(max_workers=2) as ex:
        q, w = ex.submit(discover_quick), ex.submit(discover_wide)
        return _merge(q.result() + w.result())


ESCL_MODES = {"Couleur": "RGB24", "Gris": "Grayscale8", "Noir et blanc": "BlackAndWhite1"}
ESCL_ERRORS = {
    400: "le scanner n'a pas accepté les réglages",
    409: "le scanner est occupé (une autre numérisation est peut-être en cours)",
    503: "le scanner est occupé ou en cours de préparation",
}


def _postprocess(img, wanted, used):
    if wanted == used:
        return img
    if wanted == "Grayscale8":
        return img.convert("L").convert("RGB")
    if wanted == "BlackAndWhite1":
        return img.convert("L").point(lambda p: 255 if p > 140 else 0).convert("RGB")
    return img


def scan_escl(sc, dpi, mode):
    base = sc.info["base"]
    caps = escl_caps(base, timeout=6.0, retries=3)  # réveille aussi l'imprimante si elle était en veille
    if caps is None:
        raise requests.ConnectionError("Scanner injoignable")

    w, h = int(8.27 * 300), int(11.69 * 300)  # A4 en 1/300 de pouce
    w, h = min(w, caps["maxw"] or w), min(h, caps["maxh"] or h)
    if caps["dpis"] and dpi not in caps["dpis"]:
        dpi = min(caps["dpis"], key=lambda d: abs(d - dpi))
    wanted = ESCL_MODES[mode]
    color = wanted
    if caps["modes"] and wanted not in caps["modes"]:
        color = next((m for m in ("RGB24", "Grayscale8", "BlackAndWhite1") if m in caps["modes"]), wanted)

    def settings(with_region):
        region = (
            "<pwg:ScanRegions><pwg:ScanRegion>"
            "<pwg:ContentRegionUnits>escl:ThreeHundredthsOfInches</pwg:ContentRegionUnits>"
            f"<pwg:Height>{h}</pwg:Height><pwg:Width>{w}</pwg:Width>"
            "<pwg:XOffset>0</pwg:XOffset><pwg:YOffset>0</pwg:YOffset>"
            "</pwg:ScanRegion></pwg:ScanRegions>" if with_region else "")
        return ('<?xml version="1.0" encoding="UTF-8"?>'
                '<scan:ScanSettings xmlns:pwg="http://www.pwg.org/schemas/2010/12/sm" '
                'xmlns:scan="http://schemas.hp.com/imaging/escl/2011/05/03">'
                f"<pwg:Version>2.0</pwg:Version>{region}"
                "<pwg:InputSource>Platen</pwg:InputSource>"
                f"<scan:ColorMode>{color}</scan:ColorMode>"
                f"<scan:XResolution>{dpi}</scan:XResolution><scan:YResolution>{dpi}</scan:YResolution>"
                "<pwg:DocumentFormat>image/jpeg</pwg:DocumentFormat>"
                "</scan:ScanSettings>").encode("utf-8")

    s = new_session()
    location, last_code = None, None
    for with_region in (True, False):  # 2e essai : sans zone, l'imprimante choisit elle-même
        for _ in range(4):
            r = s.post(base + "/ScanJobs", data=settings(with_region), headers={"Content-Type": "text/xml"},
                       timeout=30, allow_redirects=False)
            last_code = r.status_code
            if r.status_code in (301, 302, 307, 308) and "/ScanJobs" in r.headers.get("Location", ""):
                base = r.headers["Location"].split("/ScanJobs")[0]  # ex. l'imprimante exige https
                continue
            if r.status_code in (200, 201) and r.headers.get("Location"):
                location = r.headers["Location"]
                break
            if r.status_code in (409, 503):
                time.sleep(2)
                continue
            break
        if location:
            break
    if not location:
        raise RuntimeError(f"Numérisation refusée : {ESCL_ERRORS.get(last_code, 'code ' + str(last_code))}.")

    p = urllib.parse.urlparse(base)
    job = f"{p.scheme}://{p.netloc}{urllib.parse.urlparse(location).path}".rstrip("/")
    deadline, page = time.time() + 180, None
    while time.time() < deadline:
        page = s.get(job + "/NextDocument", timeout=120)
        if page.status_code == 200:
            break
        if page.status_code in (404, 503):  # pas encore prêt
            time.sleep(1.5)
            continue
        raise RuntimeError(f"Le scanner n'a pas renvoyé l'image (code {page.status_code}).")
    if page is None or page.status_code != 200:
        raise RuntimeError("Le scanner a mis trop de temps à répondre.")
    try:
        s.delete(job, timeout=5)
    except requests.RequestException:
        pass
    if page.content[:4] == b"%PDF":
        raise RuntimeError("Le scanner a renvoyé un PDF au lieu d'une image.")
    return _postprocess(Image.open(io.BytesIO(page.content)).convert("RGB"), wanted, color)


def _scan_wia(sc, dpi, mode):
    import win32com.client
    infos = win32com.client.Dispatch("WIA.DeviceManager").DeviceInfos
    device = None
    for i in range(1, infos.Count + 1):
        if infos[i].DeviceID == sc.info["id"]:
            device = infos[i].Connect()
    if device is None or device.Items.Count == 0:
        raise RuntimeError("Scanner injoignable via Windows. Est-il allumé et son pilote installé ?")
    item = device.Items[1]
    intent = {"Couleur": 1, "Gris": 2, "Noir et blanc": 4}[mode]
    for prop, val in (("6146", intent), ("6147", dpi), ("6148", dpi)):
        try:
            item.Properties(prop).Value = val
        except Exception:
            pass
    img = item.Transfer("{B96B3CAF-0728-11D3-9D7B-0000F81EF32E}")  # PNG
    path = os.path.join(tempfile.gettempdir(), f"wia_{int(time.time())}.png")
    img.SaveFile(path)
    out = Image.open(path).convert("RGB")
    out.load()
    os.remove(path)
    return out


def scan_sane(sc, dpi, mode):
    import sane
    dev = sane.open(sc.info["dev"])
    dev.resolution = dpi
    dev.mode = {"Couleur": "color", "Gris": "gray", "Noir et blanc": "lineart"}[mode]
    img = dev.scan().convert("RGB")
    dev.close()
    return img


def scan_wia(sc, dpi, mode):
    return _com(_scan_wia)(sc, dpi, mode)


WIA_ERRORS = {
    0x80210001: "erreur générale du scanner",
    0x80210002: "bourrage papier",
    0x80210003: "plus de papier dans le chargeur",
    0x80210005: "le scanner est hors ligne (éteint ou débranché)",
    0x80210006: "le scanner est occupé, réessayez dans un instant",
    0x8021000A: "communication impossible avec le scanner",
    0x8021000D: "le scanner est verrouillé par un autre logiciel (fermez l'application Canon/IJ Scan Utility)",
    0x80210015: "aucun scanner trouvé par Windows",
    0x80210016: "le capot du scanner est ouvert",
}


def friendly_error(e):
    hr = getattr(e, "hresult", None)
    if hr is None and e.args and isinstance(e.args[0], int):
        hr = e.args[0]
    if hr is not None:
        hr &= 0xFFFFFFFF
        if hr in WIA_ERRORS:
            return WIA_ERRORS[hr]
        detail = e.args[1] if len(e.args) > 1 and isinstance(e.args[1], str) else ""
        return f"erreur Windows 0x{hr:08X} {detail}".strip()
    return str(e)


BACKENDS = {"escl": scan_escl, "wia": scan_wia, "sane": scan_sane}

# ----------------------------------------------------------------------------
# Envoi / enregistrement
# ----------------------------------------------------------------------------


def export_pages(pages, path):
    """Écrit les pages (un PDF, ou une image par page) et renvoie la liste des fichiers créés."""
    base, ext = os.path.splitext(path)
    if ext.lower() == ".pdf":
        pages[0].save(path, "PDF", save_all=True, append_images=pages[1:], resolution=150)
        return [path]
    paths = [path] if len(pages) == 1 else [f"{base}_{i}{ext}" for i in range(1, len(pages) + 1)]
    for p, dest in zip(pages, paths):
        p.save(dest, quality=92)
    return paths


def open_mail_with_files(paths):
    """Ouvre la messagerie par défaut. Pièces jointes automatiques sous Linux ;
    ailleurs, on ouvre un message et on montre le fichier à glisser dedans."""
    if SYSTEM == "Linux":
        try:
            cmd = ["xdg-email", "--subject", "Document numérisé"]
            for p in paths:
                cmd += ["--attach", p]
            subprocess.Popen(cmd)
            return True
        except FileNotFoundError:
            pass
    webbrowser.open("mailto:?subject=" + urllib.parse.quote("Document numérisé"))
    if SYSTEM == "Windows":
        subprocess.Popen(["explorer", "/select,", os.path.normpath(paths[0])])
    elif SYSTEM == "Darwin":
        subprocess.Popen(["open", "-R", paths[0]])
    else:
        subprocess.Popen(["xdg-open", os.path.dirname(paths[0])])
    return False


# ----------------------------------------------------------------------------
# Interface : formes arrondies, sombre par défaut (mode clair en vraie couleur, jamais blanc), un seul accent bleu acier.
# Couleurs données en (mode clair, mode sombre).
# ----------------------------------------------------------------------------

BG = ("#AEBACB", "#0F1216")             # fond de la fenêtre
PANEL = ("#BFC9D7", "#171B21")          # panneau de réglages
STAGE = ("#9DAABD", "#0A0C0F")          # zone d'aperçu
INPUT = ("#CFD7E2", "#212730")          # champs, sélecteurs et boutons secondaires
HOVER = ("#B9C4D3", "#2C333E")
TEXT = ("#10151C", "#E9EEF3")
MUTED = ("#3F4B5B", "#8E9BAA")
LINE = ("#93A1B5", "#272E38")           # contours
OFF_BG = ("#B4BFCE", "#1E242C")         # bouton principal désactivé
OFF_FG = ("#6F7D90", "#5F6B79")
ACCENT = ("#26364B", "#A9BDD6")         # bleu acier
ACCENT_HI = ("#38506C", "#C6D6E8")
ON_ACCENT = ("#E8EEF5", "#10151C")
FONT = "Segoe UI"
RADIUS = 10      # boutons, champs
CARD = 14        # grands panneaux


def resource(name):
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)


class Segmented(ctk.CTkFrame):
    """Sélecteur à plusieurs choix, fait de boutons simples (texte lisible dans les deux modes)."""

    def __init__(self, parent, values, default, command=None):
        super().__init__(parent, fg_color=INPUT, corner_radius=RADIUS, border_width=0)
        self.value = default
        self.command = command
        self.buttons = {}
        for i, v in enumerate(values):
            self.grid_columnconfigure(i, weight=1, uniform="seg")
            b = ctk.CTkButton(self, text=v, height=30, corner_radius=RADIUS - 3, font=(FONT, 13),
                              command=lambda v=v: self._click(v))
            b.grid(row=0, column=i, padx=3, pady=3, sticky="ew")
            self.buttons[v] = b
        self.set(default)

    def _click(self, value):
        self.set(value)
        if self.command:
            self.command(value)

    def get(self):
        return self.value

    def set(self, value):
        self.value = value
        for v, b in self.buttons.items():
            if v == value:
                b.configure(fg_color=ACCENT, hover_color=ACCENT_HI, text_color=ON_ACCENT)
            else:
                b.configure(fg_color="transparent", hover_color=HOVER, text_color=TEXT)


class AskDialog(ctk.CTkToplevel):
    """Petite fenêtre de saisie, aux couleurs de l'application."""

    def __init__(self, parent, title, text):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.configure(fg_color=BG)
        self.resizable(False, False)
        self.transient(parent)
        ctk.CTkLabel(self, text=text, text_color=TEXT, font=(FONT, 13), wraplength=340,
                     justify="left").pack(anchor="w", padx=24, pady=(22, 10))
        self.entry = ctk.CTkEntry(self, width=340, height=36, corner_radius=RADIUS, border_width=1,
                                  fg_color=INPUT, border_color=LINE, text_color=TEXT, font=(FONT, 13))
        self.entry.pack(padx=24)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=24, pady=20)
        ctk.CTkButton(row, text="OK", width=90, height=34, corner_radius=RADIUS, fg_color=ACCENT,
                      hover_color=ACCENT_HI, text_color=ON_ACCENT, font=(FONT, 13, "bold"),
                      command=self._ok).pack(side="right")
        ctk.CTkButton(row, text="Annuler", width=90, height=34, corner_radius=RADIUS, fg_color=INPUT,
                      hover_color=HOVER, text_color=TEXT, border_width=1, border_color=LINE, font=(FONT, 13),
                      command=self.destroy).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_reqwidth()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_reqheight()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.after(150, self._focus)
        self.after(250, self._icon)

    def _focus(self):
        try:
            self.grab_set()
            self.entry.focus()
        except Exception:
            pass

    def _icon(self):
        try:
            self.iconbitmap(resource("icone.ico"))
        except Exception:
            pass

    def _ok(self):
        self.result = self.entry.get().strip()
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode(load_config().get("apparence", "dark"))
        if SYSTEM == "Windows":  # identité propre dans la barre des tâches (sinon : icône de Python)
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Scanova.Scanner")
            except Exception:
                pass
        super().__init__()
        self.title("Scanova")
        self._apply_icon()
        self.after(300, self._apply_icon)  # customtkinter remet son icône par défaut vers 200 ms
        self.geometry("1000x740")
        self.minsize(860, 700)
        self.configure(fg_color=BG)
        self.scanners, self.pages = [], []
        self._preview = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ----- Colonne de réglages (à plat, séparée de l'aperçu par un simple filet)
        side = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=CARD, width=300, border_width=1, border_color=LINE)
        side.grid(row=0, column=0, sticky="ns", padx=(16, 8), pady=16)
        side.grid_propagate(False)
        side.pack_propagate(False)

        # boutons du bas d'abord, pour qu'ils restent toujours visibles
        self.scan_btn = self._primary(side, "Numériser", self.start_scan, height=42, size=15)
        self.scan_btn.pack(fill="x", padx=24, pady=(0, 24), side="bottom")
        self.add_btn = self._secondary(side, "Ajouter une page", self.start_scan, height=36)
        self.add_btn.pack(fill="x", padx=24, pady=(0, 8), side="bottom")
        self._enable(self.add_btn, False)

        head = ctk.CTkFrame(side, fg_color="transparent")
        head.pack(fill="x", padx=24, pady=(22, 0))
        ctk.CTkLabel(head, text="Scanova", font=(FONT, 24, "bold"), text_color=TEXT).pack(side="left")
        ctk.CTkLabel(side, text="Posez le document sur la vitre, puis lancez.", text_color=MUTED,
                     font=(FONT, 12), wraplength=252, justify="left").pack(anchor="w", padx=24, pady=(4, 16))

        self._label(side, "Scanner")
        self.scanner_menu = ctk.CTkOptionMenu(
            side, values=["Recherche en cours…"], dynamic_resizing=False, anchor="w", height=34,
            corner_radius=RADIUS, font=(FONT, 13), dropdown_font=(FONT, 13), fg_color=INPUT, text_color=TEXT,
            button_color=INPUT, button_hover_color=HOVER, dropdown_fg_color=INPUT, dropdown_text_color=TEXT,
            dropdown_hover_color=HOVER)
        self.scanner_menu.pack(fill="x", padx=24)
        links = ctk.CTkFrame(side, fg_color="transparent")
        links.pack(fill="x", padx=24, pady=(8, 18))
        links.grid_columnconfigure((0, 1), weight=1, uniform="l")
        self._secondary(links, "Rechercher", lambda: self.refresh(full=True), height=30, size=12).grid(
            row=0, column=0, sticky="ew", padx=(0, 4))
        self._secondary(links, "Ajouter par IP…", self.add_ip, height=30, size=12).grid(
            row=0, column=1, sticky="ew", padx=(4, 0))

        self._label(side, "Qualité")
        self.dpi = self._segmented(side, ["150", "300", "600"], "300")
        self._label(side, "Couleurs", top=16)
        self.mode = self._segmented(side, list(ESCL_MODES), "Couleur")
        self._label(side, "Format du fichier", top=16)
        self.fmt = self._segmented(side, ["PDF", "Photo"], "PDF")
        ctk.CTkLabel(side, text="PDF pour un document, Photo pour une image JPEG.", text_color=MUTED,
                     font=(FONT, 11), wraplength=252, justify="left").pack(anchor="w", padx=24, pady=(6, 0))
        self._label(side, "Apparence", top=16)
        current = {"light": "Clair", "system": "Auto"}.get(load_config().get("apparence", "dark"), "Sombre")
        self.theme = Segmented(side, ["Auto", "Clair", "Sombre"], current, command=self.set_theme)
        self.theme.pack(fill="x", padx=24)

        # ----- Aperçu + actions
        main = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure(0, weight=1)

        self.stage = ctk.CTkFrame(main, fg_color=STAGE, corner_radius=CARD, border_width=1, border_color=LINE)
        self.stage.grid(row=0, column=0, sticky="nsew", padx=(8, 16), pady=(16, 0))
        self.preview = ctk.CTkLabel(self.stage, text="Votre document apparaîtra ici.", text_color=MUTED,
                                    font=(FONT, 14))
        self.preview.place(relx=0.5, rely=0.5, anchor="center")
        self.stage.bind("<Configure>", lambda e: self.show_last())

        self.progress = ctk.CTkProgressBar(main, mode="indeterminate", height=4, corner_radius=2, fg_color=LINE,
                                           progress_color=ACCENT)
        self.progress.grid(row=1, column=0, sticky="ew", padx=(8, 16), pady=(10, 0))
        self.progress.grid_remove()

        bar = ctk.CTkFrame(main, fg_color="transparent")
        bar.grid(row=2, column=0, sticky="ew", padx=(8, 16), pady=(10, 16))
        bar.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(bar, text="", text_color=MUTED, font=(FONT, 12), anchor="w", justify="left",
                                   wraplength=300)
        self.status.grid(row=0, column=0, sticky="w", padx=(0, 12))
        bar.bind("<Configure>", lambda e: self.status.configure(wraplength=max(120, e.width - 400)))
        self.mail_btn = self._secondary(bar, "Envoyer par e-mail", self.send_mail, height=40, size=13, width=150)
        self.mail_btn.grid(row=0, column=1, padx=(0, 8))
        self.save_btn = self._primary(bar, "Enregistrer…", self.save, height=40, size=13, width=140)
        self.save_btn.grid(row=0, column=2)
        self._enable(self.mail_btn, False)
        self._enable(self.save_btn, False, primary=True)

        self.refresh(full=False)

    # --- Petits utilitaires d'interface
    def _apply_icon(self):
        try:
            self.iconbitmap(resource("icone.ico"))
        except Exception:
            pass

    def _label(self, parent, text, top=0):
        ctk.CTkLabel(parent, text=text.upper(), text_color=MUTED, font=(FONT, 11, "bold")).pack(
            anchor="w", padx=24, pady=(top, 6))

    def _primary(self, parent, text, command, height=40, size=14, width=140):
        return ctk.CTkButton(parent, text=text, height=height, width=width, corner_radius=RADIUS, fg_color=ACCENT,
                             hover_color=ACCENT_HI, text_color=ON_ACCENT, text_color_disabled=OFF_FG,
                             font=(FONT, size, "bold"), command=command)

    def _secondary(self, parent, text, command, height=36, size=13, width=100):
        return ctk.CTkButton(parent, text=text, height=height, width=width, corner_radius=RADIUS, fg_color=INPUT,
                             hover_color=HOVER, text_color=TEXT, text_color_disabled=OFF_FG, border_width=1,
                             border_color=LINE, font=(FONT, size), command=command)

    def _segmented(self, parent, values, default):
        seg = Segmented(parent, values, default)
        seg.pack(fill="x", padx=24)
        return seg

    def _enable(self, btn, on, primary=False):
        btn.configure(state="normal" if on else "disabled")
        if primary:
            btn.configure(fg_color=ACCENT if on else OFF_BG, border_width=0)

    def set_theme(self, choice):
        mode = {"Clair": "light", "Sombre": "dark"}.get(choice, "system")
        ctk.set_appearance_mode(mode)
        update_config(lambda cfg: cfg.update(apparence=mode))

    def say(self, text):
        self.after(0, lambda: self.status.configure(text=text))

    def busy(self, on):
        if on:
            self.progress.grid()
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.grid_remove()

    # --- Recherche des scanners
    def set_scanners(self, found, select=None, previous=None):
        self.scanners = found
        names = [s.name for s in found] or ["Aucun scanner trouvé"]
        pref = preferred(found)
        choice = next((c for c in (select, previous, pref.name if pref else None) if c in names), names[0])
        self.scanner_menu.configure(values=names)
        self.scanner_menu.set(choice)
        return pref

    def refresh(self, full=True, select=None):
        previous = self.scanner_menu.get() if self.scanners else None
        self.scanner_menu.configure(values=["Recherche en cours…"])
        self.scanner_menu.set("Recherche en cours…")
        self.status.configure(text="Recherche des scanners déjà connus…" if not full else
                              "Recherche des scanners (USB et réseau), quelques secondes…")
        self._enable(self.scan_btn, False, primary=True)
        self.busy(True)
        threading.Thread(target=self._discover, args=(full, select, previous), daemon=True).start()

    def _discover(self, full, select, previous):
        try:
            if full:
                found = discover_all()
            else:
                found = discover_quick()  # 1. mémoire + Windows
                if not found:  # 2. sinon, on cherche autour
                    self.say("Aucun scanner connu trouvé, recherche autour de vous…")
                    found = discover_wide()
        except Exception:
            found = []

        def apply():
            self.busy(False)
            pref = self.set_scanners(found, select=select, previous=previous)
            self._enable(self.scan_btn, True, primary=True)
            if pref and self.scanner_menu.get() == pref.name:
                msg = f"Votre scanner habituel a été retrouvé : {pref.model}."
            elif found:
                msg = ""
            else:
                msg = ("Aucun scanner détecté. Vérifiez qu'il est allumé (réveillez-le s'il est en veille) "
                       "puis cliquez sur « Rechercher », ou utilisez « Ajouter par IP… ».")
            self.status.configure(text=msg)
        self.after(0, apply)

    def add_ip(self):
        dlg = AskDialog(self, "Ajouter un scanner",
                        "Adresse IP de l'imprimante ou du scanner (ex. 192.168.1.25) :")
        self.wait_window(dlg)
        ip = dlg.result
        if not ip:
            return
        self.status.configure(text=f"Test de {ip}…")
        self.busy(True)

        def work():
            sc = probe_escl(ip, timeout=4.0)
            if not sc:
                self.after(0, self.busy, False)
                self.say(f"Aucun scanner ne répond à l'adresse {ip}. Vérifiez l'adresse et que vous êtes sur le même réseau.")
                return
            remember_scanners([sc])
            self.after(0, lambda: self.refresh(full=False, select=sc.name))
        threading.Thread(target=work, daemon=True).start()

    # --- Numérisation
    def start_scan(self):
        sc = next((s for s in self.scanners if s.name == self.scanner_menu.get()), None)
        if not sc:
            messagebox.showinfo("Scanova", "Aucun scanner sélectionné.")
            return
        self.scan_btn.configure(text="Numérisation…")
        self._enable(self.scan_btn, False, primary=True)
        self._enable(self.add_btn, False)
        self.status.configure(text="Numérisation en cours, ne bougez pas le document.")
        self.busy(True)
        threading.Thread(target=self._scan, args=(sc, int(self.dpi.get()), self.mode.get()), daemon=True).start()

    def _relocate(self, sc):
        """L'adresse du scanner a peut-être changé : on le recherche à nouveau par son nom de modèle."""
        found = discover_all()
        new = next((s for s in found if s.kind == "escl" and s.model == sc.model), None)
        self.after(0, lambda: self.set_scanners(found, select=new.name if new else None))
        return new

    def _scan(self, sc, dpi, mode):
        try:
            used = sc
            try:
                img = BACKENDS[sc.kind](sc, dpi, mode)
            except requests.RequestException:
                if sc.kind != "escl":
                    raise
                self.say("Le scanner ne répond plus, nouvelle recherche en cours…")
                used = self._relocate(sc)
                if not used:
                    raise
                img = BACKENDS[used.kind](used, dpi, mode)
            remember_used(used)  # ce scanner sera proposé en premier la prochaine fois
            self.pages.append(img)
            self.after(0, self._scan_done)
        except requests.RequestException:
            msg = ("Le scanner ne répond pas. Vérifiez qu'il est allumé (il peut être en veille) et sur le même "
                   "Wi-Fi que l'ordinateur, puis réessayez.")
            self.after(0, lambda: self._scan_failed(msg))
        except Exception as e:
            msg = friendly_error(e)
            self.after(0, lambda: self._scan_failed(msg))

    def _scan_done(self):
        self.busy(False)
        self.scan_btn.configure(text="Recommencer")
        self._enable(self.scan_btn, True, primary=True)
        self._enable(self.add_btn, True)
        self._enable(self.mail_btn, True)
        self._enable(self.save_btn, True, primary=True)
        n = len(self.pages)
        self.status.configure(text=f"{n} page{'s' if n > 1 else ''} prête{'s' if n > 1 else ''}.")
        self.show_last()

    def _scan_failed(self, msg):
        self.busy(False)
        self.scan_btn.configure(text="Recommencer" if self.pages else "Numériser")
        self._enable(self.scan_btn, True, primary=True)
        self._enable(self.add_btn, bool(self.pages))
        self.status.configure(text="La numérisation a échoué : " + msg)

    def show_last(self):
        if not self.pages:
            return
        img = self.pages[-1]
        w, h = self.stage.winfo_width() - 40, self.stage.winfo_height() - 40
        if w < 50 or h < 50:
            return
        ratio = min(w / img.width, h / img.height)
        size = (max(1, int(img.width * ratio)), max(1, int(img.height * ratio)))
        self._preview = ctk.CTkImage(light_image=img, dark_image=img, size=size)
        self.preview.configure(image=self._preview, text="")

    # --- Sortie
    def save(self):
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        if self.fmt.get() == "PDF":
            ext, types = ".pdf", [("PDF", "*.pdf")]
        else:
            ext, types = ".jpg", [("Photo JPEG", "*.jpg"), ("Photo PNG", "*.png")]
        path = filedialog.asksaveasfilename(
            initialdir=downloads if os.path.isdir(downloads) else os.path.expanduser("~"),
            initialfile="scan" + ext, defaultextension=ext, filetypes=types)
        if path:
            files = export_pages(self.pages, path)
            self.status.configure(text=f"Enregistré : {files[0]}" + (f" (+ {len(files) - 1} autres)" if len(files) > 1 else ""))

    def send_mail(self):
        ext = ".pdf" if self.fmt.get() == "PDF" else ".jpg"
        files = export_pages(self.pages, os.path.join(tempfile.mkdtemp(prefix="scanova_"), "scan" + ext))
        attached = open_mail_with_files(files)
        self.status.configure(text="Message ouvert avec le document joint." if attached else
                              "Message ouvert. Glissez le fichier mis en évidence dans le message.")


if __name__ == "__main__":
    App().mainloop()
