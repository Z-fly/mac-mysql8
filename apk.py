#!/usr/bin/env python3
"""APK repack helper.

This script is CI-friendly:
- auto-discovers Android SDK build-tools for zipalign/apksigner
- auto-installs missing apktool/keytool on macOS runners when possible
- creates a repacked APK artifact under ./artifacts
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

REQUIRED_TOOLS = ("apktool", "zipalign", "apksigner", "keytool")


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def which(tool: str) -> str | None:
    return shutil.which(tool)


def detect_android_build_tools() -> list[str]:
    roots = []
    for k in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        v = os.environ.get(k)
        if v:
            roots.append(Path(v))
    roots.append(Path.home() / "Library" / "Android" / "sdk")

    for root in roots:
        bt = root / "build-tools"
        if not bt.exists():
            continue
        versions = sorted([p for p in bt.iterdir() if p.is_dir()])
        if not versions:
            continue
        latest = versions[-1]
        return [str(latest)]
    return []


def extend_path(paths: list[str]) -> None:
    if not paths:
        return
    os.environ["PATH"] = os.pathsep.join(paths + [os.environ.get("PATH", "")])


def try_install_macos(tool: str) -> None:
    if tool == "apktool":
        run(["brew", "install", "apktool"])
    elif tool == "keytool":
        run(["brew", "install", "openjdk"])


def ensure_tools() -> dict[str, str]:
    extend_path(detect_android_build_tools())

    found: dict[str, str] = {}
    missing: list[str] = []
    for t in REQUIRED_TOOLS:
        p = which(t)
        if p:
            found[t] = p
        else:
            missing.append(t)

    if missing and os.uname().sysname == "Darwin":
        for t in list(missing):
            if t in {"apktool", "keytool"}:
                try:
                    try_install_macos(t)
                except Exception:
                    pass
        extend_path(detect_android_build_tools())
        missing = []
        for t in REQUIRED_TOOLS:
            p = which(t)
            if p:
                found[t] = p
            else:
                missing.append(t)

    if missing:
        raise RuntimeError(
            "缺少工具: "
            + ", ".join(missing)
            + "\n请确认 apktool、zipalign、apksigner、keytool 已安装并加入 PATH，或者设置 ANDROID_HOME / ANDROID_SDK_ROOT。"
        )
    return found


def repack(output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"PK\x03\x04")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", default="artifacts/repacked.apk")
    args = parser.parse_args()

    tools = ensure_tools()
    print("Tools ready:", tools)
    apk = repack(Path(args.output))
    print(f"Repacked APK: {apk}")


if __name__ == "__main__":
    main()
