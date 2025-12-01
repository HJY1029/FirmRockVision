#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成安全的SECRET_KEY
用于Flask应用的生产环境配置
"""

import secrets
import sys

def generate_secret_key(length=32):
    """
    生成一个安全的随机密钥
    
    Args:
        length: 字节长度，默认32字节（生成64字符的十六进制字符串）
    
    Returns:
        十六进制字符串格式的密钥
    """
    return secrets.token_hex(length)

def main():
    """主函数"""
    print("=" * 80)
    print(" " * 25 + "SECRET_KEY 生成器")
    print("=" * 80)
    print()
    
    # 生成密钥
    secret_key = generate_secret_key(32)
    
    print("✅ 已生成安全的SECRET_KEY：")
    print()
    print(f"   {secret_key}")
    print()
    print("=" * 80)
    print()
    print("📋 使用方法：")
    print()
    print("1. 复制上面的密钥字符串")
    print("2. 在环境变量中设置：")
    print(f"   SECRET_KEY={secret_key}")
    print()
    print("3. 或者在Render/Railway等平台的环境变量配置中添加：")
    print(f"   键: SECRET_KEY")
    print(f"   值: {secret_key}")
    print()
    print("⚠️  重要提示：")
    print("   - 请妥善保存此密钥，不要泄露")
    print("   - 每个部署环境应使用不同的密钥")
    print("   - 如果密钥泄露，请立即更换")
    print()
    print("=" * 80)
    
    # 如果提供了命令行参数，直接输出密钥（用于脚本）
    if len(sys.argv) > 1 and sys.argv[1] == '--quiet':
        print(secret_key, end='')
        return 0
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

