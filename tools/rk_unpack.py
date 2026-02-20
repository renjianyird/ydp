import subprocess
import os

def unpack_rk_firmware(firmware_path, output_dir):
    """使用rkdeveloptool解包（需内置工具）"""
    os.makedirs(output_dir, exist_ok=True)
    # 假设已内置rkdeveloptool（需提前编译或放入工具目录）
    rk_tool = os.path.join(os.path.dirname(__file__), "rkdeveloptool")
    # 解包命令示例（需根据实际工具调整）
    subprocess.run([rk_tool, "unpack", firmware_path, output_dir], check=True)
    print(f"固件已解包到: {output_dir}")
