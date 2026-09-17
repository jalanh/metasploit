#!/usr/bin/env python3
"""
ms2012_catalog.py - local system inventory for Windows Server 2012 / 2012 R2.

Usage (from an elevated command prompt on the target server):
    python ms2012_catalog.py

Designed to run entirely from a USB drive with no installation on the
target:
  1. Copy the official Python "embeddable zip" (python.org/downloads/windows,
     e.g. python-3.12.x-embed-amd64.zip) onto the drive and extract it next
     to this script, e.g.  E:\\python\\python.exe
  2. Run:  E:\\python\\python.exe E:\\ms2012_catalog.py
  3. Results are written next to the script, under a timestamped folder.
     Nothing is written to the target's disk outside that folder, and the
     script makes no network connections.

Most sections (local security policy, audit policy, full firewall rules,
service/task enumeration) require an elevated (Run as Administrator)
command prompt. Run without elevation and the script will still produce
partial output, flagging what it couldn't collect.

Stdlib only - no pip install, so it works offline from the drive.
"""

import ctypes
import datetime
import json
import os
import socket
import subprocess
import sys
import winreg


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_cmd(args, timeout=120):
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        out = proc.stdout or ""
        if proc.returncode != 0 and proc.stderr:
            out += "\n[stderr]\n" + proc.stderr
        return out
    except FileNotFoundError:
        return "[error] command not found: %s" % args[0]
    except subprocess.TimeoutExpired:
        return "[error] command timed out after %ss: %s" % (timeout, " ".join(args))
    except Exception as exc:
        return "[error] %s" % exc


def get_installed_software():
    """Reads Uninstall registry keys instead of `wmic product`, which
    silently triggers an MSI reconfigure/repair pass for every installed
    package."""
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    entries = []
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
            except OSError:
                continue
            def opt(value_name):
                try:
                    return str(winreg.QueryValueEx(subkey, value_name)[0])
                except OSError:
                    return ""
            entries.append(
                "%-50s version=%-15s publisher=%-25s installed=%s"
                % (name, opt("DisplayVersion"), opt("Publisher"), opt("InstallDate"))
            )
    entries.sort(key=str.lower)
    return "\n".join(entries) if entries else "[none found / access denied]"


SECTIONS = [
    ("00_system_baseline", "OS version, build, edition, uptime, hardware",
        lambda: "\n\n".join([
            "== systeminfo ==\n" + run_cmd(["systeminfo"]),
            "== hostname ==\n" + run_cmd(["hostname"]),
            "== wmic os ==\n" + run_cmd(["wmic", "os", "get", "Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime", "/format:list"]),
            "== wmic computersystem ==\n" + run_cmd(["wmic", "computersystem", "get", "Manufacturer,Model,TotalPhysicalMemory,Domain,PartOfDomain", "/format:list"]),
            "== wmic cpu ==\n" + run_cmd(["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors", "/format:list"]),
            "== wmic logicaldisk ==\n" + run_cmd(["wmic", "logicaldisk", "get", "DeviceID,VolumeName,FileSystem,Size,FreeSpace", "/format:list"]),
            "== installed hotfixes (wmic qfe) ==\n" + run_cmd(["wmic", "qfe", "list", "brief", "/format:table"]),
        ])),
    ("01_users_groups_policy", "local users, groups, password/lockout policy, security/audit policy",
        lambda: "\n\n".join([
            "== net user ==\n" + run_cmd(["net", "user"]),
            "== net localgroup administrators ==\n" + run_cmd(["net", "localgroup", "administrators"]),
            "== net localgroup (all groups) ==\n" + run_cmd(["net", "localgroup"]),
            "== net accounts (password/lockout policy) ==\n" + run_cmd(["net", "accounts"]),
            "== audit policy (auditpol) ==\n" + run_cmd(["auditpol", "/get", "/category:*"]),
            "== local security policy (secedit export) ==\n" + run_secedit(),
        ])),
    ("02_network", "IP config, routes, listening ports, ARP, shares, firewall",
        lambda: "\n\n".join([
            "== ipconfig /all ==\n" + run_cmd(["ipconfig", "/all"]),
            "== route print ==\n" + run_cmd(["route", "print"]),
            "== arp -a ==\n" + run_cmd(["arp", "-a"]),
            "== netstat -ano ==\n" + run_cmd(["netstat", "-ano"]),
            "== net share ==\n" + run_cmd(["net", "share"]),
            "== firewall profile state ==\n" + run_cmd(["netsh", "advfirewall", "show", "allprofiles"]),
            "== firewall rules (see 02_network_firewall_rules.txt) ==",
        ])),
    ("02_network_firewall_rules", "full firewall rule listing (large; split out separately)",
        lambda: run_cmd(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], timeout=180)),
    ("03_software_services", "installed software, services, scheduled tasks, startup items",
        lambda: "\n\n".join([
            "== installed software (registry Uninstall keys) ==\n" + get_installed_software(),
            "== services (sc query) ==\n" + run_cmd(["wmic", "service", "get", "Name,StartMode,State,StartName", "/format:table"]),
            "== scheduled tasks ==\n" + run_cmd(["schtasks", "/query", "/fo", "LIST", "/v"], timeout=180),
            "== startup items ==\n" + run_cmd(["wmic", "startup", "get", "Caption,Command,Location,User", "/format:list"]),
        ])),
]


def run_secedit():
    tmp_cfg = os.path.join(os.environ.get("TEMP", "."), "ms2012_catalog_secpol.cfg")
    out = run_cmd(["secedit", "/export", "/cfg", tmp_cfg])
    if os.path.exists(tmp_cfg):
        try:
            with open(tmp_cfg, "r", errors="replace") as f:
                out += "\n\n" + f.read()
        finally:
            try:
                os.remove(tmp_cfg)
            except OSError:
                pass
    return out


def main():
    if os.name != "nt":
        print("This script targets Windows Server 2012/2012 R2 and must be run on Windows.")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    hostname = socket.gethostname()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(script_dir, "catalog_%s_%s" % (hostname, stamp))
    os.makedirs(out_dir, exist_ok=True)

    admin = is_admin()
    print("Running as administrator: %s" % admin)
    if not admin:
        print("WARNING: not elevated - local security policy, audit policy,")
        print("full firewall rules, and some service data will be incomplete.")

    manifest = {
        "hostname": hostname,
        "collected_at": datetime.datetime.now().isoformat(),
        "ran_as_admin": admin,
        "sections": {},
    }

    for name, description, collector in SECTIONS:
        print("Collecting: %s (%s)" % (name, description))
        try:
            content = collector()
            status = "ok"
        except Exception as exc:
            content = "[error] %s" % exc
            status = "error"
        out_path = os.path.join(out_dir, name + ".txt")
        with open(out_path, "w", errors="replace") as f:
            f.write(content)
        manifest["sections"][name] = {"description": description, "status": status, "file": name + ".txt"}

    with open(os.path.join(out_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print("\nDone. Output written to: %s" % out_dir)


if __name__ == "__main__":
    main()
