import os
import json
import hashlib
import subprocess
import requests
import time
import shutil
from pathlib import Path

class AutoYoudaoADB:
    def __init__(self):
        self.work_dir = Path.home() / "ydp_auto_workspace"
        self.work_dir.mkdir(exist_ok=True)
        self.config = {
            "device_info": None,  # 抓包获取的设备信息（仅首次需手动输入）
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

    def step1_input_device_info(self):
        """仅需手动输入一次抓包获取的设备信息（后续可缓存）"""
        print("=== 首次配置：输入抓包获取的设备信息 ===")
        self.config["device_info"] = {
            "timestamp": input("timestamp: "),
            "sign": input("sign: "),
            "mid": input("mid: "),
            "productId": input("productId: ")
        }
        with open(self.work_dir / "device_info.json", "w") as f:
            json.dump(self.config["device_info"], f)
        print("设备信息已保存，后续无需重复输入\n")

    def step2_set_password(self):
        """设置新密码（唯一需要手动输入的交互）"""
        self.config["new_password"] = input("\n请设置新的ADB密码: ").strip()
        # 自动计算带换行符的MD5（核心处理）
        password_with_newline = self.config["new_password"] + "\n"
        self.config["new_md5"] = hashlib.md5(password_with_newline.encode()).hexdigest()
        print(f"自动计算带换行符的密码MD5: {self.config['new_md5']}")

    def step3_fetch_firmware_url(self):
        """自动发送请求获取固件下载链接"""
        print("\n=== 自动获取固件链接 ===")
        if not self.config["device_info"]:
            with open(self.work_dir / "device_info.json", "r") as f:
                self.config["device_info"] = json.load(f)
        # 构造请求数据
        req_data = {**self.config["device_info"],
            "version": "99.99.90",
            "networkType": "WIFI"
        }
        # 发送请求（模拟HTTP测试网站操作）
        try:
            # 注意：实际需替换为正确的更新服务器API
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
        """自动解包固件并提取原始MD5"""
        print("\n=== 自动解包固件并提取原始MD5 ===")
        # 调用内置RK解包工具（简化版，实际可能需要适配固件格式）
        from tools.rk_unpack import unpack_rk_firmware
        unpack_dir = self.work_dir / "unpacked"
        unpack_rk_firmware(str(self.config["firmware_path"]), str(unpack_dir))
        # 查找adbd_auth.sh并提取MD5
        auth_script = next(unpack_dir.rglob("adbd_auth.sh"), None)
        if not auth_script:
            raise FileNotFoundError("未找到adbd_auth.sh，请手动提取MD5")
        with open(auth_script, "r") as f:
            content = f.read()
        self.config["original_md5"] = content.split("\"")[1]  # 提取脚本中的MD5值
        print(f"提取到原始MD5: {self.config['original_md5']}")

    def step6_modify_firmware(self):
        """自动替换固件中的MD5值"""
        print("\n=== 自动修改固件 ===")
        # 复制固件为修改版
        shutil.copy2(self.config["firmware_path"], self.config["modified_firmware"])
        # 调用内置工具替换十六进制中的MD5
        from tools.hex_replace import replace_hex_in_file
        replace_hex_in_file(
            str(self.config["modified_firmware"]),
            self.config["original_md5"].encode(),
            self.config["new_md5"].encode()
        )
        print(f"已替换MD5，修改后固件: {self.config['modified_firmware']}")

    def step7_calculate_checksums(self):
        """自动计算校验值"""
        print("\n=== 自动计算校验值 ===")
        # 计算整体MD5
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_md5"] = hashlib.md5(f.read()).hexdigest()
        # 计算SHA256
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_sha256"] = hashlib.sha256(f.read()).hexdigest()
        print(f"整体MD5: {self.config['total_md5']}")
        print(f"SHA256: {self.config['total_sha256']}")

    def step8_start_servers(self):
        """自动启动HTTP服务器和修改hosts（需管理员权限）"""
        print("\n=== 自动启动服务器 ===")
        # 启动HTTP服务器（后台线程）
        def run_http():
            os.chdir(str(self.config["modified_firmware"].parent))
            subprocess.run(["python", "-m", "http.server", str(self.config["server_port"])], check=True)
        import threading
        threading.Thread(target=run_http, daemon=True).start()
        print(f"HTTP服务器启动: http://{self.config['local_ip']}:{self.config['server_port']}")

        # 自动修改hosts（Windows示例，需管理员权限）
        if os.name == "nt":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            with open(hosts_path, "r+") as f:
                content = f.read()
                if "iotapi.abupdate.com" not in content:
                    f.write(f"\n{self.config['local_ip']} iotapi.abupdate.com\n")
            subprocess.run(["ipconfig", "/flushdns"], check=True)
            print("已修改hosts并刷新DNS")

    def step9_guide_update(self):
        """提示用户在设备上操作更新"""
        print("\n=== 设备更新引导 ===")
        print("1. 确保词典笔连接到本机热点")
        print("2. 在词典笔上执行「检查更新」")
        input("更新完成并重启后按回车继续...")

    def step10_verify_adb(self):
        """自动验证ADB连接"""
        print("\n=== 自动验证ADB ===")
        # 假设设备IP为192.168.1.10（实际可能需要手动输入）
        device_ip = input("请输入词典笔IP: ")
        # 自动执行ADB命令
        try:
            subprocess.run(["adb", "connect", device_ip], check=True, timeout=10)
            # 发送密码验证（通过管道输入密码）
            proc = subprocess.Popen(
                ["adb", "shell", "auth"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=self.config["new_password"], timeout=10)
            if "success" in stdout:
                print("ADB连接成功！已获取权限")
            else:
                print(f"验证失败: {stderr}")
        except Exception as e:
            print(f"ADB操作失败: {e}")

    def run(self):
        print("=== 有道词典笔ADB自动配置工具 ===")
        print("注意：操作有风险，可能导致设备异常！\n")
        try:
            # 仅首次需要手动输入设备信息
            if not (self.work_dir / "device_info.json").exists():
                self.step1_input_device_info()
            self.step2_set_password()          # 唯一需要手动输入的密码
            self.step3_fetch_firmware_url()    # 自动
            self.step4_download_firmware()     # 自动
            self.step5_extract_original_md5()  # 自动（依赖解包工具）
            self.step6_modify_firmware()       # 自动（依赖十六进制替换）
            self.step7_calculate_checksums()   # 自动
            self.step8_start_servers()         # 自动（需权限）
            self.step9_guide_update()          # 需设备操作
            self.step10_verify_adb()           # 自动验证
        except Exception as e:
            print(f"流程中断: {e}")
        print("\n操作结束")

if __name__ == "__main__":
    tool = AutoYoudaoADB()
    tool.run()
