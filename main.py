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
        # 下载目录改为程序运行的同目录
        self.work_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.work_dir.mkdir(exist_ok=True)
        self.config = {
            "device_info": None,
            "new_password": None,
            "firmware_url": None,
            "firmware_path": self.work_dir / "full_package.img",
            "modified_firmware": self.work_dir / "modified_package.img",
            "local_ip": self.get_local_ip(),
            "server_port": 14514,
            "captured": False  # 标记是否完成抓包
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
        print("=== 【步骤1：自动抓包】请让词典笔连接当前网络并点击「检查更新」 ===")
        print("提示：抓包将持续60秒，超时会自动转为手动输入")
        device_info = {}

        # 抓包回调函数：过滤更新请求
        def capture_callback(packet):
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
                            device_info.update({
                                "timestamp": req_json["timestamp"],
                                "sign": req_json["sign"],
                                "mid": req_json["mid"],
                                "productId": req_json["productId"]
                            })
                            self.config["captured"] = True
                            print("\n✅ 成功捕获设备信息！")
                            print(f"timestamp: {device_info['timestamp']}")
                            print(f"sign: {device_info['sign']}")
                            print(f"mid: {device_info['mid']}")
                            print(f"productId: {device_info['productId']}")
                            # 停止抓包
                            raise KeyboardInterrupt
                except:
                    pass

        # 开始抓包（监听所有网络接口，持续60秒）
        try:
            sniff(prn=capture_callback, timeout=60, store=0)
        except KeyboardInterrupt:
            pass

        if not self.config["captured"]:
            print("\n❌ 抓包超时，请手动输入设备信息")
            self.step1_input_device_info()
        else:
            self.config["device_info"] = device_info
            with open(self.work_dir / "device_info.json", "w") as f:
                json.dump(device_info, f)

    def step1_input_device_info(self):
        """手动输入设备信息（抓包失败时备用）"""
        print("\n=== 【步骤1：手动输入设备信息】请输入抓包获取的参数 ===")
        self.config["device_info"] = {
            "timestamp": input("timestamp: "),
            "sign": input("sign: "),
            "mid": input("mid: "),
            "productId": input("productId: ")
        }
        self.config["captured"] = True
        with open(self.work_dir / "device_info.json", "w") as f:
            json.dump(self.config["device_info"], f)

    def step2_set_password(self):
        """设置新密码（抓包完成后才执行）"""
        if not self.config["captured"]:
            print("\n❌ 请先完成抓包，再设置密码")
            self.step1_auto_capture_device_info()
        print("\n=== 【步骤2：设置ADB密码】 ===")
        self.config["new_password"] = input("请设置新的ADB密码: ").strip()
        password_with_newline = self.config["new_password"] + "\n"
        self.config["new_md5"] = hashlib.md5(password_with_newline.encode()).hexdigest()
        print(f"自动计算带换行符的密码MD5: {self.config['new_md5']}")

    def step3_fetch_firmware_url(self):
        """自动获取固件链接（抓包完成后才执行）"""
        if not self.config["device_info"]:
            if (self.work_dir / "device_info.json").exists():
                with open(self.work_dir / "device_info.json", "r") as f:
                    self.config["device_info"] = json.load(f)
                    self.config["captured"] = True
            else:
                print("\n❌ 请先完成抓包，再获取固件链接")
                self.step1_auto_capture_device_info()

        print("\n=== 【步骤3：获取固件链接】 ===")
        req_data = {**self.config["device_info"],
            "version": "99.99.90",
            "networkType": "WIFI"
        }
        try:
            print("正在向服务器请求固件链接...")
            resp = requests.post(
                "https://iotapi.abupdate.com/product/ota/checkVersion",
                json=req_data,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            resp.raise_for_status()
            resp_json = resp.json()
            if "data" in resp_json and "version" in resp_json["data"]:
                self.config["firmware_url"] = resp_json["data"]["version"]["fullUrl"]  # 改为全量包链接
                print(f"成功获取固件链接: {self.config['firmware_url']}")
            else:
                raise ValueError("响应中无固件链接")
        except Exception as e:
            print(f"获取链接失败: {e}")
            self.config["firmware_url"] = input("请手动输入全量包固件链接: ")

    def step4_download_firmware(self):
        """自动下载固件（保存到程序同目录，增加重试）"""
        if not self.config["firmware_url"]:
            self.step3_fetch_firmware_url()

        print("\n=== 【步骤4：下载固件】 ===")
        if self.config["firmware_path"].exists():
            print(f"固件已存在: {self.config['firmware_path']}，跳过下载")
            return
        
        max_retries = 3
        for retry in range(max_retries):
            try:
                print(f"开始下载（第{retry+1}次尝试）: {self.config['firmware_url']}")
                print(f"保存路径: {self.config['firmware_path']}")
                with requests.get(self.config["firmware_url"], stream=True, timeout=30) as r:
                    r.raise_for_status()
                    with open(self.config["firmware_path"], "wb") as f:
                        for chunk in r.iter_content(chunk_size=1024*1024):  # 1MB分块下载
                            if chunk:
                                f.write(chunk)
                                print(f"已下载: {f.tell()//1024//1024}MB", end="\r")
                print(f"\n下载完成，大小: {self.config['firmware_path'].stat().st_size // 1024 // 1024}MB")
                return
            except Exception as e:
                print(f"\n下载失败: {e}")
                if retry < max_retries - 1:
                    print("3秒后重试...")
                    time.sleep(3)
        raise Exception("多次下载失败，请检查网络或手动下载固件到该路径")

    def step5_extract_original_md5(self):
        """自动解包并提取原始MD5（简化版）"""
        print("\n=== 【步骤5：解包固件】 ===")
        if not self.config["firmware_path"].exists():
            self.step4_download_firmware()
        
        unpack_dir = self.work_dir / "unpacked"
        unpack_dir.mkdir(exist_ok=True)
        # 假设固件是zip格式（实际需根据固件类型调整）
        try:
            shutil.unpack_archive(str(self.config["firmware_path"]), str(unpack_dir))
        except:
            print("解包失败，请手动解包固件")
            unpack_dir = Path(input("请输入手动解包的目录路径: "))
        
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
        print("\n=== 【步骤6：修改固件】 ===")
        if not self.config["firmware_path"].exists():
            self.step4_download_firmware()
        
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
                    print("✅ MD5替换成功")
                    return
        raise ValueError("未找到需要替换的MD5值，请手动替换")

    def step7_calculate_checksums(self):
        """自动计算校验值"""
        print("\n=== 【步骤7：计算校验值】 ===")
        if not self.config["modified_firmware"].exists():
            self.step6_modify_firmware()
        
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_md5"] = hashlib.md5(f.read()).hexdigest()
        with open(self.config["modified_firmware"], "rb") as f:
            self.config["total_sha256"] = hashlib.sha256(f.read()).hexdigest()
        print(f"修改后固件MD5: {self.config['total_md5']}")
        print(f"修改后固件SHA256: {self.config['total_sha256']}")

    def step8_start_servers(self):
        """自动启动服务器"""
        print("\n=== 【步骤8：启动服务器】 ===")
        if not self.config["modified_firmware"].exists():
            self.step6_modify_firmware()
        
        def run_http():
            os.chdir(str(self.config["modified_firmware"].parent))
            subprocess.run(["python", "-m", "http.server", str(self.config["server_port"])], check=True)
        import threading
        threading.Thread(target=run_http, daemon=True).start()
        print(f"HTTP服务器启动: http://{self.config['local_ip']}:{self.config['server_port']}")

        # 修改hosts
        if os.name == "nt":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            try:
                with open(hosts_path, "r+") as f:
                    content = f.read()
                    if "iotapi.abupdate.com" not in content:
                        f.write(f"\n{self.config['local_ip']} iotapi.abupdate.com\n")
                subprocess.run(["ipconfig", "/flushdns"], check=True)
                print("✅ 已修改hosts并刷新DNS")
            except PermissionError:
                print("❌ 请以管理员权限运行程序，否则无法修改hosts")

    def step9_guide_update(self):
        """提示设备操作"""
        print("\n=== 【步骤9：设备更新】 ===")
        print("1. 确保词典笔连接到当前网络")
        print("2. 在词典笔上点击「检查更新」并安装修改后的固件")
        input("更新完成并重启设备后，按回车键继续...")

    def step10_verify_adb(self):
        """自动验证ADB"""
        print("\n=== 【步骤10：验证ADB】 ===")
        adb_path = self.work_dir / "adb.exe"
        if not adb_path.exists():
            print("❌ 未找到ADB工具，请确保程序同目录下有adb.exe")
            return
        
        device_ip = input("请输入词典笔的IP地址: ")
        try:
            print(f"正在连接: {device_ip}")
            subprocess.run([str(adb_path), "connect", device_ip], check=True, timeout=10)
            proc = subprocess.Popen(
                [str(adb_path), "shell", "auth"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=self.config["new_password"], timeout=10)
            if "success" in stdout.lower():
                print("✅ ADB权限验证成功！")
            else:
                print(f"❌ 验证失败: {stderr}")
        except Exception as e:
            print(f"❌ ADB操作失败: {e}")

    def run(self):
        print("=== 有道词典笔ADB自动配置工具 ===")
        print("提示：请以管理员权限运行本程序，否则可能无法抓包/修改hosts\n")
        try:
            # 强制先执行抓包
            if not (self.work_dir / "device_info.json").exists() or not self.config["captured"]:
                self.step1_auto_capture_device_info()
            # 按流程执行
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
            print(f"\n❌ 流程中断: {str(e)}")
        print("\n=== 操作结束 ===")


if __name__ == "__main__":
    tool = AutoYoudaoADB()
    tool.run()
