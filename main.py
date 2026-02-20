import os
import json
import hashlib
import subprocess
import time
import shutil
from pathlib import Path


class AutoYoudaoADB:
    def __init__(self):
        # 工作目录为程序同目录
        self.work_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.config = {
            "new_password": None,
            "firmware_path": None,  # 手动指定的本地全量包路径
            "modified_firmware": self.work_dir / "modified_package.img",
            "local_ip": self.get_local_ip(),
            "server_port": 14514,
            "original_md5": None,   # 从固件中提取的原始MD5
            "new_md5": None         # 新密码的MD5
        }

    def get_local_ip(self):
        """获取本机局域网IP"""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def step1_select_firmware(self):
        """手动选择本地全量包"""
        print("=== 【步骤1：选择本地全量包】 ===")
        default_path = self.work_dir / "full_package.img"
        if default_path.exists():
            use_default = input(f"检测到同目录下有full_package.img，是否使用？(y/n): ").strip().lower()
            if use_default == 'y':
                self.config["firmware_path"] = default_path
                print(f"已选择固件：{self.config['firmware_path']}")
                return
        
        # 手动输入路径
        while True:
            firmware_path = input("请输入本地全量包的路径（如D:/firmware.img）: ").strip()
            if Path(firmware_path).exists():
                self.config["firmware_path"] = Path(firmware_path)
                print(f"已选择固件：{self.config['firmware_path']}")
                break
            else:
                print("路径不存在，请重新输入！")

    def step2_set_password(self):
        """设置新ADB密码并计算MD5"""
        print("\n=== 【步骤2：设置ADB密码】 ===")
        while True:
            self.config["new_password"] = input("请设置新的ADB密码: ").strip()
            confirm = input("请再次确认密码: ").strip()
            if self.config["new_password"] == confirm and self.config["new_password"]:
                break
            print("密码不一致或为空，请重新输入！")
        
        # 计算带换行符的MD5（关键步骤，与固件逻辑匹配）
        password_with_newline = self.config["new_password"] + "\n"
        self.config["new_md5"] = hashlib.md5(password_with_newline.encode()).hexdigest()
        print(f"自动计算带换行符的密码MD5: {self.config['new_md5']}")

    def step3_extract_original_md5(self):
        """从固件中提取原始MD5（支持手动提取备用）"""
        print("\n=== 【步骤3：提取原始MD5】 ===")
        # 自动解包提取（假设固件是zip格式，根据实际格式调整）
        unpack_dir = self.work_dir / "unpacked"
        unpack_dir.mkdir(exist_ok=True)
        try:
            print("正在自动解包固件...")
            shutil.unpack_archive(str(self.config["firmware_path"]), str(unpack_dir))
        except Exception as e:
            print(f"自动解包失败：{e}，请手动解包后提取adbd_auth.sh中的MD5")
            self.config["original_md5"] = input("请手动输入从adbd_auth.sh中提取的原始MD5: ").strip()
            return
        
        # 自动查找adbd_auth.sh并提取MD5
        auth_script = next(unpack_dir.rglob("adbd_auth.sh"), None)
        if not auth_script:
            print("未找到adbd_auth.sh，请手动提取MD5")
            self.config["original_md5"] = input("请输入原始MD5: ").strip()
            return
        
        with open(auth_script, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # 假设MD5在类似 'echo "xxx"' 的格式中，根据实际内容调整
        if '"' in content:
            self.config["original_md5"] = content.split('"')[1].strip()
            print(f"自动提取到原始MD5: {self.config['original_md5']}")
        else:
            print("未识别到MD5格式，请手动输入")
            self.config["original_md5"] = input("请输入原始MD5: ").strip()

    def step4_modify_firmware(self):
        """替换固件中的MD5为新密码的MD5"""
        print("\n=== 【步骤4：修改固件】 ===")
        if not self.config["original_md5"] or not self.config["new_md5"]:
            print("缺少原始MD5或新MD5，无法修改！")
            return
        
        # 复制固件为修改版（保留原文件）
        shutil.copy2(self.config["firmware_path"], self.config["modified_firmware"])
        print(f"正在修改固件：{self.config['modified_firmware']}")
        
        # 替换文件中的原始MD5为新MD5（二进制替换，保证文件大小不变）
        with open(self.config["modified_firmware"], "r+b") as f:
            original_bytes = self.config["original_md5"].encode()
            new_bytes = self.config["new_md5"].encode()
            if len(original_bytes) != len(new_bytes):
                print("MD5长度不匹配，替换失败！")
                return
            
            replaced = False
            while True:
                pos = f.tell()
                chunk = f.read(len(original_bytes))
                if not chunk:
                    break
                if chunk == original_bytes:
                    f.seek(pos)
                    f.write(new_bytes)
                    replaced = True
                    break
            
            if replaced:
                print("✅ MD5替换成功，修改后的固件已保存")
            else:
                print("❌ 未找到需要替换的MD5，请手动用WinHex替换")

    def step5_calculate_checksums(self):
        """计算修改后固件的校验值（用于验证完整性）"""
        print("\n=== 【步骤5：计算校验值】 ===")
        if not self.config["modified_firmware"].exists():
            print("未找到修改后的固件，跳过校验！")
            return
        
        with open(self.config["modified_firmware"], "rb") as f:
            md5 = hashlib.md5(f.read()).hexdigest()
        with open(self.config["modified_firmware"], "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        
        print(f"修改后固件MD5: {md5}")
        print(f"修改后固件SHA256: {sha256}")
        with open(self.work_dir / "checksums.txt", "w") as f:
            f.write(f"MD5: {md5}\nSHA256: {sha256}")
        print("校验值已保存到checksums.txt")

    def step6_start_servers(self):
        """启动本地HTTP服务器并修改hosts（劫持更新请求）"""
        print("\n=== 【步骤6：启动服务器】 ===")
        if not self.config["modified_firmware"].exists():
            print("未找到修改后的固件，无法启动服务器！")
            return
        
        # 启动HTTP服务器（提供修改后的固件）
        def run_http_server():
            os.chdir(str(self.config["modified_firmware"].parent))
            subprocess.run(["python", "-m", "http.server", str(self.config["server_port"])], check=True)
        
        import threading
        server_thread = threading.Thread(target=run_http_server, daemon=True)
        server_thread.start()
        time.sleep(2)  # 等待服务器启动
        print(f"HTTP服务器已启动：http://{self.config['local_ip']}:{self.config['server_port']}")
        
        # 修改hosts（将更新服务器指向本机）
        if os.name == "nt":
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            try:
                with open(hosts_path, "r+", encoding="utf-8") as f:
                    content = f.read()
                    target_line = f"{self.config['local_ip']} iotapi.abupdate.com"
                    if target_line not in content:
                        f.write(f"\n{target_line}\n")
                        print("已修改hosts文件，劫持更新请求到本机")
                    else:
                        print("hosts已配置，无需修改")
                subprocess.run(["ipconfig", "/flushdns"], check=True)
                print("DNS缓存已刷新")
            except PermissionError:
                print("❌ 请以管理员权限运行程序，否则无法修改hosts！")
            except Exception as e:
                print(f"修改hosts失败：{e}，请手动添加一行：{target_line}")

    def step7_guide_update(self):
        """指导用户在设备上执行更新"""
        print("\n=== 【步骤7：设备更新】 ===")
        print("1. 确保词典笔连接到与电脑相同的网络")
        print("2. 在词典笔上操作：设置 → 系统更新 → 检查更新")
        print("3. 等待设备下载并安装修改后的固件（可能需要重启）")
        input("设备完成更新并重启后，按回车键继续验证ADB...")

    def step8_verify_adb(self):
        """验证ADB连接（使用内置或同目录的adb.exe）"""
        print("\n=== 【步骤8：验证ADB】 ===")
        adb_path = self.work_dir / "adb.exe"
        if not adb_path.exists():
            print("未在程序目录找到adb.exe，尝试使用系统环境中的adb...")
            adb_path = "adb"  # 假设系统环境变量中有adb
        
        device_ip = input("请输入词典笔的IP地址（可在设备网络设置中查看）: ").strip()
        try:
            # 连接设备
            print(f"正在连接 {device_ip}...")
            subprocess.run([str(adb_path), "connect", device_ip], check=True, timeout=10)
            
            # 验证密码
            print(f"正在验证密码...")
            proc = subprocess.Popen(
                [str(adb_path), "shell", "auth"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=self.config["new_password"], timeout=10)
            
            if "success" in stdout.lower() or proc.returncode == 0:
                print("✅ ADB验证成功！已获得设备权限")
            else:
                print(f"❌ 验证失败，输出：{stderr or stdout}")
        except Exception as e:
            print(f"ADB操作失败：{e}")

    def run(self):
        print("=== 有道词典笔ADB配置工具（本地固件版） ===")
        print("说明：此版本从本地全量包开始处理，需提前准备好固件文件\n")
        try:
            self.step1_select_firmware()      # 选择本地固件
            self.step2_set_password()         # 设置密码
            self.step3_extract_original_md5() # 提取原始MD5
            self.step4_modify_firmware()      # 替换MD5
            self.step5_calculate_checksums()  # 计算校验值
            self.step6_start_servers()        # 启动服务器
            self.step7_guide_update()         # 指导更新
            self.step8_verify_adb()           # 验证ADB
        except KeyboardInterrupt:
            print("\n程序被手动终止")
        except Exception as e:
            print(f"\n流程出错：{str(e)}")
        print("\n=== 所有步骤结束 ===")


if __name__ == "__main__":
    tool = AutoYoudaoADB()
    tool.run()
