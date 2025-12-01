#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 部署前检查脚本
检查部署所需的所有文件和配置
"""

import os
import sys
from pathlib import Path

def check_file_exists(filepath, description):
    """检查文件是否存在"""
    if Path(filepath).exists():
        print(f"✅ {description}: {filepath}")
        return True
    else:
        print(f"❌ {description}: {filepath} - 文件不存在")
        return False

def check_directory_exists(dirpath, description):
    """检查目录是否存在"""
    if Path(dirpath).is_dir():
        print(f"✅ {description}: {dirpath}")
        return True
    else:
        print(f"⚠️  {description}: {dirpath} - 目录不存在（将自动创建）")
        return True  # 目录会自动创建，不算错误

def check_models():
    """检查模型文件"""
    models_dir = Path('models')
    if not models_dir.exists():
        print("❌ models/ 目录不存在")
        return False
    
    model_files = list(models_dir.glob('*.pkl'))
    if len(model_files) == 0:
        print("⚠️  models/ 目录中没有模型文件（.pkl）")
        print("   提示: 运行 python main.py --step train 训练模型")
        return False
    
    print(f"✅ 找到 {len(model_files)} 个模型文件")
    return True

def check_preprocessor():
    """检查预处理器文件"""
    preprocessor = Path('processed_data/preprocessor.pkl')
    if preprocessor.exists():
        print(f"✅ 预处理器文件: {preprocessor}")
        return True
    else:
        print(f"⚠️  预处理器文件不存在: {preprocessor}")
        print("   提示: 运行 python main.py --step preprocess 生成预处理器")
        return False

def main():
    """主检查函数"""
    print("=" * 80)
    print(" " * 25 + "部署前检查")
    print("=" * 80)
    print()
    
    all_ok = True
    
    # 检查必需文件
    print("【必需文件检查】")
    files_to_check = [
        ('Procfile', 'Procfile'),
        ('runtime.txt', 'Python版本文件'),
        ('requirements.txt', '依赖文件'),
        ('wsgi.py', 'WSGI入口文件'),
        ('app.py', 'Flask应用主文件'),
        ('Dockerfile', 'Docker配置文件'),
    ]
    
    for filepath, desc in files_to_check:
        if not check_file_exists(filepath, desc):
            all_ok = False
    
    print()
    
    # 检查目录
    print("【目录检查】")
    dirs_to_check = [
        ('templates', '模板目录'),
        ('static', '静态文件目录'),
        ('routes', '路由目录'),
    ]
    
    for dirpath, desc in dirs_to_check:
        check_directory_exists(dirpath, desc)
    
    print()
    
    # 检查模型文件
    print("【模型文件检查】")
    if not check_models():
        all_ok = False
    
    print()
    
    # 检查预处理器
    print("【预处理器检查】")
    if not check_preprocessor():
        all_ok = False
    
    print()
    
    # 检查环境变量配置
    print("【环境变量检查】")
    secret_key = os.environ.get('SECRET_KEY', '')
    if secret_key and secret_key != 'your-secret-key-change-this-in-production':
        print("✅ SECRET_KEY 已设置")
    else:
        print("⚠️  SECRET_KEY 未设置或使用默认值")
        print("   提示: 在生产环境中必须设置强随机SECRET_KEY")
    
    flask_env = os.environ.get('FLASK_ENV', '')
    if flask_env == 'production':
        print("✅ FLASK_ENV=production")
    else:
        print(f"ℹ️  FLASK_ENV={flask_env or '未设置'}")
    
    print()
    
    # 总结
    print("=" * 80)
    if all_ok:
        print("✅ 基本检查通过！可以开始部署。")
    else:
        print("⚠️  发现一些问题，请先解决后再部署。")
    print("=" * 80)
    
    return 0 if all_ok else 1

if __name__ == '__main__':
    sys.exit(main())

