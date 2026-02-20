def replace_hex_in_file(file_path, old_bytes, new_bytes):
    """在文件中替换十六进制内容（确保长度一致）"""
    if len(old_bytes) != len(new_bytes):
        raise ValueError("替换前后长度必须一致")
    with open(file_path, "r+b") as f:
        while True:
            pos = f.tell()
            chunk = f.read(len(old_bytes))
            if not chunk:
                break
            if chunk == old_bytes:
                f.seek(pos)
                f.write(new_bytes)
                print("MD5替换成功")
                return
    raise ValueError("未找到需要替换的MD5值")

