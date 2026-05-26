#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用途：
    生成一个 APK 分析题。原始 APK 来自用户上传的 JustTrustMe_.4.apk。
    脚本会随机生成一个 Android 包名，把内置 APK 真正反编译、修改、重打包、对齐、签名。
    考生需要从生成的 APK 中解析出 package 包名。

依赖真实命令：
    apktool（PATH 缺少时自动下载并校验官方 JAR，需要 java）
    zipalign
    apksigner
    keytool

macOS 示例：
    安装 Android SDK build-tools 后，把 zipalign/apksigner 加入 PATH

Linux 示例：
    安装 openjdk-17-jdk
    安装 Android SDK build-tools 后，把 zipalign/apksigner 加入 PATH
"""

from argparse import ArgumentParser
from base64 import b64decode
from hashlib import sha256
from json import dumps
from pathlib import Path
from random import choices
from shutil import copyfileobj, rmtree, which
from string import ascii_lowercase, digits
from subprocess import run, PIPE, STDOUT
from urllib.error import URLError
from urllib.request import urlopen
import os
import re
import tempfile
import xml.etree.ElementTree as ET


APKTOOL版本 = "3.0.2"
APKTOOL_JAR文件名 = f"apktool_{APKTOOL版本}.jar"
APKTOOL下载地址 = (
    f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL版本}/"
    f"{APKTOOL_JAR文件名}"
)
APKTOOL_SHA256 = "eee4669a704a14e0623407e6701b0b91887e61e1e4049cb7a82833e14ae8b5fd"


# 原始检材 APK 已硬编码，不需要额外提供 APK 文件。
原始APK_BASE64 = """
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
AAAAAAAAAAAPAAAAHQAAAAwMSGVsbG8gd29ybGQhAAsLSnVzdFRydXN0TWUACAhTZXR0aW5ncwAA
AiABQAQAAH8AAABqAHUAcwB0AC4AdAByAHUAcwB0AC4AbQBlAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAEAAAAAAAB0AQAAAAAAAAAA
AAABABwAVAAAAAMAAAAAAAAAAAAAACgAAAAAAAAAAAAAAA4AAAAeAAAABQBkAGkAbQBlAG4AAAAG
AHMAdAByAGkAbgBnAAAABQBzAHQAeQBsAGUAAAABABwApAAAAAYAAAAAAAAAAAEAADQAAAAAAAAA
AAAAAB0AAAA4AAAASgAAAFUAAABjAAAAGhphY3Rpdml0eV9ob3Jpem9udGFsX21hcmdpbgAYGGFj
dGl2aXR5X3ZlcnRpY2FsX21hcmdpbgAPD2FjdGlvbl9zZXR0aW5ncwAICGFwcF9uYW1lAAsLaGVs
bG9fd29ybGQACAhBcHBUaGVtZQAAAAICEAAYAAAAAQAAAAIAAAAAAgAAAAAAAAECVAB8AAAAAQAA
AAIAAABcAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAACAAAAAAAAAAIAAAFARAAAAgAAAABAAAACAAABQEQAAAB
AlQAbAAAAAEAAAACAAAAXAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANAMAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wgAAAAAAAAACAAABQFAAAACAhAAHAAA
AAIAAAADAAAAAAAAAAAAAAAAAAAAAQJUAJAAAAACAAAAAwAAAGAAAABAAAAAAAAAAAAAAAAAAAAA
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
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4DwAAAAAAAEFQSyBTaWcgQmxvY2sgNDJQSwEC
AAAAAAAACAAAAAAA513hr4UCAAD4BgAAEwAAAAAAAAAAAAAAAAAAAAAAQW5kcm9pZE1hbmlmZXN0
LnhtbFBLAQIYABQAAAAIAAAAAACuVEmfDgQAAM4EAAARAAAAAAAAAAAAAAAAALYCAABNRVRBLUlO
Ri9DRVJULlJTQVBLAQIYABQAAAAIAAAAAACGx/BxGQEAAJQBAAAQAAAAAAAAAAAAAAAAAPMGAABN
RVRBLUlORi9DRVJULlNGUEsBAhgAFAAAAAgAAAAAAPVu6ir9AAAAaQEAABQAAAAAAAAAAAAAAAAA
OggAAE1FVEEtSU5GL01BTklGRVNULk1GUEsBAhgAFAAAAAgAAAAAABDBTe0RAAAAEgAAABIAAAAA
AAAAAAAAAAAAaQkAAGFzc2V0cy94cG9zZWRfaW5pdFBLAQIYABQAAAAIAAAAAACNOPebiyAAAHhO
AAALAAAAAAAAAAAAAAAAAKoJAABjbGFzc2VzLmRleFBLAQIAAAAAAAAAAAAAAAAE7qDxnAQAAJwE
AAAOABIAAAAAAAAAAAAAAF4qAAByZXNvdXJjZXMuYXJzYzXZDgAEAAAAAAAAAAAAAAAAAFBLBQYA
AAAABwAHAMcBAAA4PwAAAAA=
"""


def 运行命令(命令, 工作目录=None):
    print("[命令]", " ".join(map(str, 命令)))
    结果 = run(
        list(map(str, 命令)),
        cwd=str(工作目录) if 工作目录 else None,
        stdout=PIPE,
        stderr=STDOUT,
        text=True
    )
    if 结果.returncode != 0:
        print(结果.stdout)
        raise RuntimeError("命令执行失败: " + " ".join(map(str, 命令)))
    if 结果.stdout.strip():
        print(结果.stdout.strip())
    return 结果.stdout


def 查找Android工具(工具名):
    """
    优先用 PATH。
    如果 PATH 找不到，再尝试从 ANDROID_HOME / ANDROID_SDK_ROOT 的 build-tools 目录里找。
    """
    路径 = which(工具名)
    if 路径:
        return 路径

    SDK根目录列表 = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        str(Path.home() / "Library" / "Android" / "sdk"),
        str(Path.home() / "Android" / "Sdk"),
    ]

    for SDK根目录 in SDK根目录列表:
        if not SDK根目录:
            continue

        build_tools目录 = Path(SDK根目录) / "build-tools"
        if not build_tools目录.exists():
            continue

        候选版本目录列表 = sorted(build_tools目录.iterdir(), reverse=True)
        for 版本目录 in 候选版本目录列表:
            候选路径 = 版本目录 / 工具名
            if 候选路径.exists():
                return str(候选路径)

    return None


def 计算文件SHA256(文件路径):
    摘要 = sha256()
    with 文件路径.open("rb") as 文件:
        for 数据块 in iter(lambda: 文件.read(1024 * 1024), b""):
            摘要.update(数据块)
    return 摘要.hexdigest()


def 准备Apktool命令():
    """
    GitHub 托管 runner 通常自带 Java 和 Android build-tools，但不带 apktool。
    优先使用 PATH；缺少时下载固定版本官方 JAR，并在执行前校验摘要。
    """
    apktool路径 = which("apktool")
    if apktool路径:
        return [apktool路径]

    java路径 = which("java")
    if not java路径:
        raise RuntimeError(
            "缺少工具: apktool，且未找到 java，无法运行自动下载的 apktool JAR。"
        )

    指定JAR = os.environ.get("APKTOOL_JAR")
    if 指定JAR:
        指定JAR路径 = Path(指定JAR).expanduser()
        if not 指定JAR路径.is_file():
            raise RuntimeError("APKTOOL_JAR 指定的文件不存在: " + str(指定JAR路径))
        print("[+] 使用 APKTOOL_JAR:", 指定JAR路径)
        return [java路径, "-jar", str(指定JAR路径.resolve())]

    缓存根目录 = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    缓存目录 = 缓存根目录 / "apk_repack_challenge"
    缓存JAR路径 = 缓存目录 / APKTOOL_JAR文件名

    if 缓存JAR路径.is_file() and 计算文件SHA256(缓存JAR路径) == APKTOOL_SHA256:
        print("[+] 使用已缓存的 apktool JAR:", 缓存JAR路径)
        return [java路径, "-jar", str(缓存JAR路径)]

    缓存目录.mkdir(parents=True, exist_ok=True)
    临时JAR路径 = 缓存目录 / f".{APKTOOL_JAR文件名}.{os.getpid()}.tmp"
    print("[+] PATH 未找到 apktool，正在下载:", APKTOOL下载地址)

    try:
        with urlopen(APKTOOL下载地址, timeout=120) as 响应:
            with 临时JAR路径.open("wb") as 临时JAR文件:
                copyfileobj(响应, 临时JAR文件)

        实际摘要 = 计算文件SHA256(临时JAR路径)
        if 实际摘要 != APKTOOL_SHA256:
            raise RuntimeError(
                "下载的 apktool JAR 校验失败: "
                f"期望 {APKTOOL_SHA256}，实际 {实际摘要}"
            )

        临时JAR路径.replace(缓存JAR路径)
    except (OSError, URLError) as 异常:
        raise RuntimeError(
            "自动下载 apktool 失败，请检查网络，或安装 apktool / 设置 APKTOOL_JAR。"
        ) from 异常
    finally:
        临时JAR路径.unlink(missing_ok=True)

    print("[+] apktool JAR 下载并校验完成:", 缓存JAR路径)
    return [java路径, "-jar", str(缓存JAR路径)]


def 检查工具():
    工具映射 = {
        "apktool": 准备Apktool命令(),
        "zipalign": 查找Android工具("zipalign"),
        "apksigner": 查找Android工具("apksigner"),
        "keytool": which("keytool"),
    }

    缺少列表 = [名字 for 名字, 路径 in 工具映射.items() if not 路径]
    if 缺少列表:
        raise RuntimeError(
            "缺少工具: " + ", ".join(缺少列表) + "\n"
            "请确认 apktool、zipalign、apksigner、keytool 已安装并加入 PATH，"
            "或者设置 ANDROID_HOME / ANDROID_SDK_ROOT。"
        )

    return 工具映射


def 生成文件名():
    后缀 = ''.join(choices(ascii_lowercase + digits, k=10))
    return f"apk_{后缀}.apk"


def 生成包名片段(长度):
    首字符 = choices(ascii_lowercase, k=1)[0]
    剩余字符 = "".join(choices(ascii_lowercase + digits, k=长度 - 1))
    return 首字符 + 剩余字符


def 生成包名():
    return f"com.{生成包名片段(8)}.{生成包名片段(6)}"


def 写出原始APK(路径):
    路径.write_bytes(b64decode(原始APK_BASE64))
    print("[+] 已写出原始 APK:", 路径)


def 反编译APK(apktool命令, 输入APK, 输出目录):
    if 输出目录.exists():
        rmtree(输出目录)

    运行命令([
        *apktool命令,
        "d",
        "-f",
        str(输入APK),
        "-o",
        str(输出目录)
    ])


def 修改Manifest包名(解包目录, 新包名):
    Manifest路径 = 解包目录 / "AndroidManifest.xml"
    if not Manifest路径.exists():
        raise RuntimeError("apktool 解包后没有找到 AndroidManifest.xml")

    # apktool 解出来的是文本 XML，这里修改 manifest 的 package 属性。
    树 = ET.parse(Manifest路径)
    根节点 = 树.getroot()

    旧包名 = 根节点.attrib.get("package")
    if not 旧包名:
        raise RuntimeError("AndroidManifest.xml 里没有 package 属性")

    根节点.set("package", 新包名)
    树.write(Manifest路径, encoding="utf-8", xml_declaration=True)

    print(f"[+] Manifest package: {旧包名} -> {新包名}")
    return 旧包名


def 修改ApktoolYml(解包目录, 新包名):
    """
    有些 apktool 版本会在 apktool.yml 里保存 renameManifestPackage。
    这里不是必须，但写上可以避免个别版本回编译时把包名还原。
    """
    yml路径 = 解包目录 / "apktool.yml"
    if not yml路径.exists():
        return

    文本 = yml路径.read_text(encoding="utf-8", errors="ignore")

    if "renameManifestPackage:" in 文本:
        文本 = re.sub(
            r"(?m)^renameManifestPackage:.*$",
            f"renameManifestPackage: {新包名}",
            文本
        )
    else:
        文本 += f"\nrenameManifestPackage: {新包名}\n"

    yml路径.write_text(文本, encoding="utf-8")
    print("[+] 已同步 apktool.yml")


def 重新打包APK(apktool命令, 解包目录, 未签名APK):
    if 未签名APK.exists():
        未签名APK.unlink()

    运行命令([
        *apktool命令,
        "b",
        str(解包目录),
        "-o",
        str(未签名APK)
    ])


def 生成签名证书(keytool路径, 证书路径):
    if 证书路径.exists():
        return

    运行命令([
        keytool路径,
        "-genkeypair",
        "-v",
        "-keystore",
        str(证书路径),
        "-alias",
        "ctfkey",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "10000",
        "-storepass",
        "android",
        "-keypass",
        "android",
        "-dname",
        "CN=CTF,O=Challenge,C=CN"
    ])
    print("[+] 已生成签名证书:", 证书路径)


def 对齐APK(zipalign路径, 未签名APK, 对齐APK):
    if 对齐APK.exists():
        对齐APK.unlink()

    运行命令([
        zipalign路径,
        "-p",
        "-f",
        "4",
        str(未签名APK),
        str(对齐APK)
    ])
    print("[+] zipalign 完成:", 对齐APK)


def 签名APK(apksigner路径, 对齐APK, 输出APK, 证书路径):
    if 输出APK.exists():
        输出APK.unlink()

    运行命令([
        apksigner路径,
        "sign",
        "--ks",
        str(证书路径),
        "--ks-key-alias",
        "ctfkey",
        "--ks-pass",
        "pass:android",
        "--key-pass",
        "pass:android",
        "--out",
        str(输出APK),
        str(对齐APK)
    ])
    print("[+] apksigner 签名完成:", 输出APK)


def 验证APK签名(apksigner路径, 输出APK):
    运行命令([
        apksigner路径,
        "verify",
        "--verbose",
        str(输出APK)
    ])


def 生成题目(输出路径=None):
    工具 = 检查工具()

    答案 = 生成包名()
    文件名 = 生成文件名()

    if 输出路径:
        输出目录 = Path(输出路径)
        if not 输出目录.is_absolute():
            输出目录 = Path(__file__).resolve().parent / 输出目录
        输出目录.mkdir(parents=True, exist_ok=True)
        文件名 = str(输出目录 / 文件名)

    输出APK = Path(文件名).resolve()

    with tempfile.TemporaryDirectory(prefix="apk_repack_challenge_") as 临时目录文本:
        临时目录 = Path(临时目录文本)
        原始APK = 临时目录 / "原始检材.apk"
        解包目录 = 临时目录 / "apktool_out"
        未签名APK = 临时目录 / "unsigned.apk"
        对齐后APK = 临时目录 / "aligned.apk"
        证书路径 = 临时目录 / "ctf.keystore"

        写出原始APK(原始APK)
        反编译APK(工具["apktool"], 原始APK, 解包目录)

        修改Manifest包名(解包目录, 答案)
        修改ApktoolYml(解包目录, 答案)

        重新打包APK(工具["apktool"], 解包目录, 未签名APK)
        生成签名证书(工具["keytool"], 证书路径)
        对齐APK(工具["zipalign"], 未签名APK, 对齐后APK)
        签名APK(工具["apksigner"], 对齐后APK, 输出APK, 证书路径)
        验证APK签名(工具["apksigner"], 输出APK)

    参考格式 = 生成包名()

    结果 = {
        "fileName": Path(文件名).name,
        "answer": 答案,
        "referenceFormat": 参考格式
    }

    print(dumps(结果, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    参数解析器 = ArgumentParser()
    参数解析器.add_argument("-o", dest="输出路径", metavar="路径", help="生成的检材保存目录")
    参数 = 参数解析器.parse_args()

    生成题目(参数.输出路径)
