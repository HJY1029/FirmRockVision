#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试服务器是否运行
"""

import socket
import requests
import time

def test_port(port):
    """测试端口是否开放"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def test_http(port):
    """测试HTTP响应"""
    try:
        response = requests.get(f'http://127.0.0.1:{port}', timeout=2)
        return True, response.status_code
    except requests.exceptions.ConnectionError:
        return False, "连接被拒绝"
    except requests.exceptions.Timeout:
        return False, "连接超时"
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 60)
    print("测试服务器连接")
    print("=" * 60)
    
    ports = [5000, 5001, 8080]
    
    for port in ports:
        print(f"\n测试端口 {port}:")
        if test_port(port):
            print(f"  [OK] 端口 {port} 已开放")
            success, info = test_http(port)
            if success:
                print(f"  [OK] HTTP响应正常 (状态码: {info})")
                print(f"\n  >>> 服务器正在运行！访问地址: http://127.0.0.1:{port}")
                return
            else:
                print(f"  [X] HTTP测试失败: {info}")
        else:
            print(f"  [X] 端口 {port} 未开放")
    
    print("\n" + "=" * 60)
    print("未找到运行中的服务器")
    print("=" * 60)
    print("\n请运行以下命令启动服务器:")
    print("  python app.py")
    print("  或")
    print("  python start_server.py")

if __name__ == '__main__':
    main()

