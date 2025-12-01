#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动服务器（带详细错误检查）
"""

import sys
import traceback

def main():
    print("=" * 80)
    print("启动服务器...")
    print("=" * 80)
    
    try:
        # 检查并导入
        print("\n[1/5] 检查依赖...")
        from flask import Flask
        print("  [OK] Flask")
        
        print("\n[2/5] 导入应用模块...")
        import app
        print("  [OK] app.py")
        
        print("\n[3/5] 初始化数据库...")
        from db_handler import init_database
        init_database()
        print("  [OK] 数据库初始化完成")
        
        print("\n[4/5] 初始化分析器...")
        init_success, init_message = app.init_analyzer()
        if not init_success:
            print(f"  [警告] {init_message}")
            print("  服务器仍会启动，但检测功能可能不可用")
        else:
            print(f"  [OK] {init_message}")
        
        print("\n[5/5] 注册路由...")
        app.register_all_routes()
        print("  [OK] 路由注册完成")
        
        # 检查端口
        import socket
        port = 5000
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                print(f"\n[警告] 端口 {port} 已被占用，尝试端口 5001...")
                port = 5001
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    print(f"[警告] 端口 {port} 也被占用，尝试端口 8080...")
                    port = 8080
        except:
            pass
        
        print("\n" + "=" * 80)
        print(" " * 15 + "磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - Web平台")
        print("=" * 80)
        print(f"\n系统状态: {init_message}")
        print(f"数据库: detection.db")
        print("\n启动Web服务器...")
        print(f"访问地址: http://127.0.0.1:{port}")
        print(f"          http://localhost:{port}")
        print("\n按 Ctrl+C 停止服务器")
        print("=" * 80)
        print("\n如果无法访问，请检查：")
        print("  1. 防火墙是否阻止了端口")
        print("  2. 浏览器是否使用了正确的地址")
        print("  3. 查看下方是否有错误信息")
        print("=" * 80 + "\n")
        
        # 启动服务器
        app.app.run(debug=True, host='0.0.0.0', port=port, use_reloader=False)
        
    except KeyboardInterrupt:
        print("\n\n服务器已停止")
    except Exception as e:
        print("\n" + "=" * 80)
        print("启动失败！")
        print("=" * 80)
        print(f"\n错误类型: {type(e).__name__}")
        print(f"错误信息: {str(e)}")
        print("\n详细错误信息:")
        traceback.print_exc()
        print("\n" + "=" * 80)
        sys.exit(1)

if __name__ == '__main__':
    main()

