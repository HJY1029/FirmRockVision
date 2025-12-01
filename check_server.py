#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查服务器状态
"""

import socket
import sys

def check_port(host='127.0.0.1', port=5000):
    """检查端口是否被占用"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def main():
    print("=" * 60)
    print("服务器状态检查")
    print("=" * 60)
    
    # 检查端口
    if check_port():
        print("[X] 端口 5000 已被占用")
        print("    请先停止其他使用该端口的程序")
        print("    或者修改 app.py 中的端口号")
    else:
        print("[OK] 端口 5000 可用")
    
    # 检查导入
    print("\n检查模块导入...")
    try:
        import app
        print("[OK] app.py 导入成功")
    except Exception as e:
        print(f"[X] app.py 导入失败: {e}")
        sys.exit(1)
    
    try:
        from routes.detect import register_detect_routes
        print("[OK] routes.detect 导入成功")
    except Exception as e:
        print(f"[X] routes.detect 导入失败: {e}")
        sys.exit(1)
    
    try:
        from db_handler import init_database
        print("[OK] db_handler 导入成功")
    except Exception as e:
        print(f"[X] db_handler 导入失败: {e}")
        sys.exit(1)
    
    try:
        from file_processor import read_csv_file
        print("[OK] file_processor 导入成功")
    except Exception as e:
        print(f"[X] file_processor 导入失败: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("[OK] 所有检查通过！")
    print("=" * 60)
    print("\n启动服务器:")
    print("  python app.py")
    print("\n如果端口被占用，可以:")
    print("  1. 停止占用端口的程序")
    print("  2. 或修改 app.py 第122行，改为其他端口，如: port=5001")

if __name__ == '__main__':
    main()

