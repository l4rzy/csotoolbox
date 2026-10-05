#!/usr/bin/env python3
# Client/publish.py - Build and package self-update ready bundles
import os
import sys
import re
import shutil
import subprocess
import hashlib
import zipfile
import json

def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_zip(source_dir, output_zip_path):
    # Ensure the parent directory of the output ZIP exists
    os.makedirs(os.path.dirname(output_zip_path), exist_ok=True)
    
    # Excluded files, extensions, and directory names
    excluded_names = {"config.ini", "config.json", "state.data"}
    excluded_extensions = {".pdb", ".db", ".sqlite", ".db-journal", ".log", ".dbg"}

    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            # Check if we are inside a 'dbs' directory (e.g. database directory)
            rel_root = os.path.relpath(root, source_dir)
            if rel_root != ".":
                parts = rel_root.split(os.sep)
                if "dbs" in parts:
                    continue

            for file in files:
                # Check explicit names
                if file.lower() in excluded_names:
                    continue
                
                # Check extensions
                _, ext = os.path.splitext(file)
                if ext.lower() in excluded_extensions:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, source_dir)
                zipf.write(full_path, rel_path)

def main():
    # Ensure we are in the Client directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # 1. Detect configuration from Client.csproj
    csproj_path = "Client.csproj"
    if not os.path.exists(csproj_path):
        print(f"Error: {csproj_path} not found.")
        sys.exit(1)

    with open(csproj_path, "r", encoding="utf-8") as f:
        csproj_content = f.read()

    framework_match = re.search(r'<(TargetFramework|TargetFrameworks)>(.*?)</\1>', csproj_content)
    version_match = re.search(r'<Version>(.*?)</Version>', csproj_content)

    if not framework_match or not version_match:
        print("Error: Could not parse TargetFramework or Version from Client.csproj")
        sys.exit(1)

    framework_raw = framework_match.group(2).strip()
    frameworks = [f.strip() for f in framework_raw.split(';')]
    win_framework = next((f for f in frameworks if "windows" in f), frameworks[0])
    linux_framework = next((f for f in frameworks if "linux" in f or "windows" not in f), frameworks[0])
    version = version_match.group(1).strip()

    # Parse arguments
    if "--bump" in sys.argv:
        version_parts = version.split('.')
        try:
            version_parts[-1] = str(int(version_parts[-1]) + 1)
            new_version = '.'.join(version_parts)
            csproj_content = re.sub(r'<Version>(.*?)</Version>', f'<Version>{new_version}</Version>', csproj_content)
            with open(csproj_path, "w", encoding="utf-8") as f:
                f.write(csproj_content)
            print(f"Bumped version from {version} to {new_version} in Client.csproj")
            version = new_version
        except Exception as e:
            print(f"Warning: Failed to bump version: {e}")

    transitional = False
    if "--transitional" in sys.argv or "--raw" in sys.argv:
        transitional = True

    platform = "both"
    # Support '--platform <value>'
    if "--platform" in sys.argv:
        try:
            idx = sys.argv.index("--platform")
            val = sys.argv[idx + 1].lower()
            if val in ("windows", "win", "win-x64"):
                platform = "windows"
            elif val in ("linux", "linux-x64"):
                platform = "linux"
            elif val == "both":
                platform = "both"
            else:
                print(f"Error: Unknown platform value '{val}'. Expected 'windows', 'linux', or 'both'.")
                sys.exit(1)
        except IndexError:
            print("Error: Missing value for --platform option.")
            sys.exit(1)
    
    # Support explicit flags: --windows, --linux, --both
    if "--windows" in sys.argv:
        platform = "windows"
    elif "--linux" in sys.argv:
        platform = "linux"
    elif "--both" in sys.argv:
        platform = "both"

    print("==============================================")
    print(f"Preparing Update-Ready Bundle for v{version}")
    print(f"Target Framework: {framework_raw}")
    print(f"Target Platform: {platform.upper()}")
    print("==============================================")

    win_rid = "win-x64"
    linux_rid = "linux-x64"

    win_bundle_name = f"CSOToolbox-{version}-win64.exe" if transitional else f"CSOToolbox-{version}-win64.zip"
    linux_bundle_name = f"CSOToolbox-{version}-linux64" if transitional else f"CSOToolbox-{version}-linux64.zip"

    # 2. Run Publish
    publish_args = [
        "publish",
        "-c", "Release",
        "--self-contained", "true",
        "/p:PublishSingleFile=true",
        "/p:IncludeNativeLibrariesForSelfContained=true",
        "/p:PublishTrimmed=true",
        "/p:TrimMode=full",
        "/p:EnableCompressionInSingleFile=true",
        "/p:ReleaseChannel=PROD"
    ]

    if platform in ("windows", "both"):
        print(f"Publishing for Windows ({win_rid}) using {win_framework}...")
        subprocess.run(["dotnet"] + publish_args + ["-r", win_rid, "-f", win_framework], check=True)

    if platform in ("linux", "both"):
        print(f"Publishing for Linux ({linux_rid}) using {linux_framework}...")
        subprocess.run(["dotnet"] + publish_args + ["-r", linux_rid, "-f", linux_framework], check=True)

    # 3. Locate Published Executables
    win_src_exe = os.path.join("bin", "Release", win_framework, win_rid, "publish", "Client.exe")
    linux_src_exe = os.path.join("bin", "Release", linux_framework, linux_rid, "publish", "Client")

    if platform in ("windows", "both") and not os.path.exists(win_src_exe):
        print(f"Error: Published Windows binary not found at: {win_src_exe}")
        sys.exit(1)

    if platform in ("linux", "both") and not os.path.exists(linux_src_exe):
        print(f"Error: Published Linux binary not found at: {linux_src_exe}")
        sys.exit(1)

    # 4. Package binaries and dependencies to Server/updates/
    updates_dir = os.path.join("..", "Server", "updates")
    os.makedirs(updates_dir, exist_ok=True)

    # Clean up all old update files
    print(f"Cleaning up old update files in {updates_dir}...")
    for filename in os.listdir(updates_dir):
        if re.match(r"^CSOToolbox-.*-win64\.(zip|exe)$", filename) or \
           re.match(r"^CSOToolbox-.*-linux64(\.zip)?$", filename):
            file_path = os.path.join(updates_dir, filename)
            try:
                os.remove(file_path)
                print(f"Deleted old update file: {filename}")
            except Exception as e:
                print(f"Warning: Failed to delete {filename}: {e}")

    win_pub_dir = os.path.dirname(win_src_exe)
    linux_pub_dir = os.path.dirname(linux_src_exe)

    win_bundle_path = os.path.join(updates_dir, win_bundle_name)
    linux_bundle_path = os.path.join(updates_dir, linux_bundle_name)

    # Remove existing update files if they exist
    if platform in ("windows", "both") and os.path.exists(win_bundle_path):
        os.remove(win_bundle_path)
    if platform in ("linux", "both") and os.path.exists(linux_bundle_path):
        os.remove(linux_bundle_path)

    if transitional:
        print(f"Creating transitional raw binaries in {updates_dir}...")
        if platform in ("windows", "both"):
            shutil.copy2(win_src_exe, win_bundle_path)
        if platform in ("linux", "both"):
            shutil.copy2(linux_src_exe, linux_bundle_path)
    else:
        if platform in ("windows", "both"):
            print(f"Creating Windows zip archive in {win_bundle_path}...")
            create_zip(win_pub_dir, win_bundle_path)
        if platform in ("linux", "both"):
            print(f"Creating Linux zip archive in {linux_bundle_path}...")
            create_zip(linux_pub_dir, linux_bundle_path)

    # 5. Compute sizes and SHA-256 hashes
    print("Computing sizes and SHA-256 hashes...")
    win_sha = get_sha256(win_bundle_path) if platform in ("windows", "both") else None
    linux_sha = get_sha256(linux_bundle_path) if platform in ("linux", "both") else None

    win_size = os.path.getsize(win_bundle_path) if platform in ("windows", "both") else 0
    linux_size = os.path.getsize(linux_bundle_path) if platform in ("linux", "both") else 0

    # 6. Generate/update latest.json manifest
    manifest_path = os.path.join(updates_dir, "latest.json")
    data = {
        "version": version,
        "release_notes": f"Update to version {version}",
        "platforms": {}
    }

    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                if "release_notes" in existing:
                    data["release_notes"] = existing["release_notes"]
                if "platforms" in existing:
                    data["platforms"] = existing["platforms"]
        except Exception as e:
            print(f"Warning: Could not parse existing manifest: {e}")

    # Read release notes from custom file if exists
    notes_path = "release_notes.txt"
    if os.path.exists(notes_path):
        try:
            with open(notes_path, "r", encoding="utf-8") as f:
                data["release_notes"] = f.read().strip()
                print("Release notes loaded from release_notes.txt")
        except Exception as e:
            print(f"Warning: Could not read release_notes.txt: {e}")

    if platform in ("windows", "both"):
        data["platforms"]["win-x64"] = {
            "filename": win_bundle_name,
            "sha256": win_sha,
            "size": win_size
        }
    
    if platform in ("linux", "both"):
        data["platforms"]["linux-x64"] = {
            "filename": linux_bundle_name,
            "sha256": linux_sha,
            "size": linux_size
        }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Successfully updated update manifest: {manifest_path}")

    print("==============================================")
    print("Publishing & Packaging Complete!")
    print(f"Version: {version}")
    if platform in ("windows", "both"):
        print(f"Windows: {win_bundle_name} (Size: {win_size} bytes)")
    if platform in ("linux", "both"):
        print(f"Linux: {linux_bundle_name} (Size: {linux_size} bytes)")
    print("==============================================")

if __name__ == "__main__":
    main()
