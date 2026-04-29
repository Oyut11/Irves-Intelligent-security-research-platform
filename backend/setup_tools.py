#!/usr/bin/env python3
"""
IRVES — Auto-provisioning Script
Downloads and configures APKTool, JADX, and Frida to ensure a 
frictionless onboarding setup.
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import stat
from pathlib import Path
import platform

APKTOOL_JAR = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar"
APKTOOL_SCRIPT = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"

# Use JADX zip release
JADX_URL = "https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip"

def download(url, dest):
    print(f"Downloading {url} to {dest}...")
    urllib.request.urlretrieve(url, dest, timeout=300)

def setup_tools():
    # Target directory inside user's local bin
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    tools_dir = Path.home() / ".irves" / "bin"
    tools_dir.mkdir(parents=True, exist_ok=True)

    print(f"⚙️ Setting up IRVES dependencies in {tools_dir}...")

    # 1. APKTool
    apktool_jar_path = tools_dir / "apktool.jar"
    apktool_bin_path = bin_dir / "apktool"
    if not apktool_jar_path.exists():
        download(APKTOOL_JAR, apktool_jar_path)
    if not apktool_bin_path.exists():
        download(APKTOOL_SCRIPT, apktool_bin_path)
        apktool_bin_path.chmod(apktool_bin_path.stat().st_mode | stat.S_IEXEC)
        # Update script to point to jar location
        script_content = apktool_bin_path.read_text()
        script_content = script_content.replace("apktool.jar", str(apktool_jar_path))
        apktool_bin_path.write_text(script_content)

    # 2. JADX
    jadx_extracted_dir = tools_dir / "jadx"
    jadx_symlink = bin_dir / "jadx"
    if not jadx_extracted_dir.exists():
        zip_path = tools_dir / "jadx.zip"
        download(JADX_URL, zip_path)
        print("Extracting JADX...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(jadx_extracted_dir)
        zip_path.unlink()
        
        # Make scripts executable
        for script in (jadx_extracted_dir / "bin").iterdir():
            script.chmod(script.stat().st_mode | stat.S_IEXEC)
    
    if not jadx_symlink.exists():
        try:
            jadx_symlink.symlink_to(jadx_extracted_dir / "bin" / "jadx")
        except Exception as e:
            print(f"Warning: Could not symlink jadx: {e}")

    # 3. Python Packages (Frida & Mitmproxy)
    print("📦 Installing required python binaries (Frida-tools, Mitmproxy)...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "frida-tools", "mitmproxy", "pygments"
    ])

    # 4. Ensure ~/.local/bin is in PATH
    bashrc = Path.home() / ".bashrc"
    path_line = f'export PATH="$PATH:{bin_dir}"'
    if bashrc.exists() and path_line not in bashrc.read_text():
        with bashrc.open("a") as f:
            f.write(f"\n# IRVES tools\n{path_line}\n")
        print(f"📝 Added {bin_dir} to ~/.bashrc")

    print("\n✅ Setup Complete!")
    print(f"Run: source ~/.bashrc  (or open a new terminal) to activate PATH changes.")

if __name__ == '__main__':
    try:
        setup_tools()
    except Exception as e:
        print(f"❌ Error during setup: {e}")
        sys.exit(1)
