import os
import json
import hashlib
import subprocess
import requests
import time
import shutil
from pathlib import Path
from scapy.all import sniff, TCP, Raw  # 用于抓包


class AutoYoudaoADB:
    def __init__(self):
        self.work_dir = Path.home() / "ydp_auto_workspace"
        self.work_dir.mkdir(exist_ok=True)
        self.config = {
            "device_info": None,
            "new_password": None,
            "firmware_url": None,
            "firmware_path": self.work_dir / "full_package.img",
            "modified_firmware": self.work_dir / "modified_package.img",
            "local_ip": self.get_local_ip(),
            "server_port": 14514
        }

    def get_local_ip(self):
        """自动获取本机局域网IP"""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def step1_auto_capture_device_info(self):
        """内置抓包：自动捕获词典笔的更新请求参数"""
        print("=== 自动抓包：请让词典笔连接当前网络并点击「检查更新」 ===")
        captured = False
        device_info = {}

        # 抓包回调函数：过滤更新请求
        def capture_callback(packet):
            nonlocal captured, device_info
            if TCP in packet and packet[TCP].dport == 443 and Raw in packet:
                try:
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    # 匹配更新请求的接口路径
                    if "/ota/checkVersion" in payload and "productId" in payload:
                        # 提取JSON参数
                        json_start = payload.find("{")
                        json_end = payload.rfind("}") + 1
                        if json_start != -1 and json_end != -1:
                            req_json = json.loads(payload[json_start:json_end])
                            device_info = {
                                "timestamp": req_json["timestamp"],
                                "sign": req_json["sign"],
                                "mid": req_json["mid"],
                                "productId": req_json["productId"]
                            }
                            captured = True
                            print("✅ 成功捕获设备信息！")
                except:
                    pass

        # 开始抓包（监听所有网络接口，持续1分钟）
        sniff(prn=capture_callback, timeout=60, store=0)
        if not captured:
            print("❌ 抓包超时，请手动输入设备信息")
            self.step1_input_device_info()
        else:
            self.config["device_info"] = device_info
            with open(self.work_dir / "device_info.json", "w") as f:
                json.dump(device_info, f)

    def step1_input_device_info(self):
        """手动输入设备信息（抓包失败时备用）"""
        print("=== 手动输入抓包获取的设备信息 ===")
        self.config["device_info"] = {
            "timestamp": input("timestamp: "),
            "sign": input("sign: "),
            "mid": input("mid: "),
            "productId": input("productId: ")
        }
        with open(self.work_dir / "device_info.json", "w") as f:
            json.dump(self.config["device_info"], f)

    def step2_set_password(self):
        """设置新密码"""
        self.config["new_password"] = input("\n请设置新的ADB密码: ").strip()
        password_with_newline = self.config["new_password"] + "\n"
        self.config["new_md5"] = hashlib.md5(password_with_newline.encode()).hexdigest()
        print(f"自动计算带换行符的密码MD5: {self.config['new_md5']}")

    def step3_fetch_firmware_url(self):
        """自动获取固件链接"""
        print("\n=== 自动获取固件链接 ===")
        if not self.config["device_info"]:
            with open(self.work_dir / "device_info.json", "r") as f:
                self.config["device_info"] = json.load(f)
        req_data = {**self.config["device_info"],
            "version": "99.99.90",
            "networkType": "WIFI"
        }
        try:
            resp = requests.post(
                "https://iotapi.abupdate.com/product/ota/checkVersion",
                json=req_data,
                headers={"Content-Type": "application/json"}
            )
            resp.raise_for_status()
            self.config["firmware_url"] = resp.json()["data"]["version"]["deltaUrl"]
            print(f"成功获取固件链接: {self.config['firmware_url']}")
        except Exception as e:
            print(f"获取链接失败，请手动输入: {e}")
            self.config["firmware_url"] = input("手动输入固件链接: ")

    def step4_download_firmware(self):
        """自动下载固件"""
        print("\n=== 自动下载固件 ===")
        if self.config["firmware_path"].exists():
            print("固件已存在，跳过下载")
            return
        print(f"开始下载到: {self.config['firmware_path']}")
        with requests.get(self.config["firmware_url"], stream=True) as r:
            r.raise_for_status()
            with open(self.config["firmware_path"], "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"下载完成，大小: {self.config['firmware_path'].stat().st_size // 1024 // 1024}MB")

    def step5_extract_original_md5(self):
        """自动解包并提取原始MD5（简化版）"""
        print("\n=== 自动解包固件 ===")
        # 这里需要根据固件格式调整解包逻辑（示例为RK固件）
        unpack_dir = self.work_dir / "unpacked"
        unpack_dir.mkdir(exist_ok=True)
        # 假设固件是zip格式（实际需适配）
        shutil.unpack_archive(str(self.config["firmware_path"]), str(unpack_dir))
        # 查找adbd_auth.sh
        auth_script = next(unpack_dir.rglob("adbd_auth.sh"), None)
        if not auth_script:
            raise FileNotFoundError("未找到adbd_auth.sh，请手动提取MD5")
        with open(auth_script, "r") as f:
            content = f.read()
        self.config["original_md5"] = content.split("\"")[1]
        print(f"提取到原始MD5: {self.config['original_md5']}")

    def step6_modify_firmware(self):
        """自动替换MD5"""
        print("\n=== 自动修改固件 ===")
        shutil.copy2(self.config["firmware_path"], self.config["modified_firmware"])
        # 替换Hex内容
        with open(self.config["modified_firmware"], "r+b") as f:
            while True:
                pos = f.tell()
                chunk = f.read(len(self.config["original_md5"].encode()))
                if not chunk:
                    break
                if chunk == self.config["original_md5"].encode():
                    f.seek(pos)
                    f.write(self.config["new_md5"].encode())
                    print("MD5替换成功")
                    return
        raise ValueError("未找到需要替换的MD5值")

    def step7_calculate_checksums(self):
        """自动计算校验值"""
        print("\n=== 自动计算校验值 ===")
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_md5"] = hashlib.md5(f.read()).hexdigest()
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_sha256"] = hashlib.sha256(f.read()).hexdigest()
        print(f"整体MD5: {self.config['total_md5']}")
        print(f"SHA256: {self.config['total_sha256']}")

    def step8_start_servers(self):
        """自动启动服务器"""
        print("\n=== 自动启动服务器 ===")
        def run_http():
            os.chdir(str(self.config["modified_firmware"].parent))
            subprocess.run(["python", "-m", "http.server", str(self.config["server_port"])], check=True)
        import threading
        threading.Thread(target=run_http, daemon=True).start()
        print(f"HTTP服务器启动: http://{self.config['local_ip']}:{self.config['server_port']}")

        # 修改hosts
        if os.name == "nt":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            with open(hosts_path, "r+") as f:
                content = f.read()
                if "iotapi.abupdate.com" not in content:
                    f.write(f"\n{self.config['local_ip']} iotapi.abupdate.com\n")
            subprocess.run(["ipconfig", "/flushdns"], check=True)
            print("已修改hosts并刷新DNS")

    def step9_guide_update(self):
        """提示设备操作"""
        print("\n=== 设备更新引导 ===")
        print("1. 确保词典笔连接到当前网络")
        print("2. 在词典笔上点击「检查更新」并安装")
        input("更新完成并重启后按回车继续...")

    def step10_verify_adb(self):
        """自动验证ADB"""
        print("\n=== 自动验证ADB ===")
        device_ip = input("请输入词典笔IP: ")
        try:
            subprocess.run(["adb", "connect", device_ip], check=True, timeout=10)
            proc = subprocess.Popen(
                ["adb", "shell", "auth"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=self.config["new_password"], timeout=10)
            if "success" in stdout:
                print("✅ ADB连接成功！已获取权限")
            else:
                print(f"❌ 验证失败: {stderr}")
        except Exception as e:
            print(f"❌ ADB操作失败: {e}")

    def run(self):
        print("=== 有道词典笔ADB自动配置工具 ===")
        print("注意：需以管理员权限运行！\n")
        try:
            if not (self.work_dir / "device_info.json").exists():
                self.step1_auto_capture_device_info()  # 自动抓包
            self.step2_set_password()
            self.step3_fetch_firmware_url()
            self.step4_download_firmware()
            self.step5_extract_original_md5()
            self.step6_modify_firmware()
            self.step7_calculate_checksums()
            self.step8_start_servers()
            self.step9_guide_update()
            self.step10_verify_adb()
        except Exception as e:
            print(f"流程中断: {e}")
        print("\n操作结束")


if __name__ == "__main__":
    tool = AutoYoudaoADB()
    tool.run()
