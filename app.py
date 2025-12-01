#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - Web平台
Flask Web应用主文件（重构版）
"""

from flask import Flask, render_template, jsonify
from pathlib import Path
from detection_analyzer import DetectionAnalyzer
from db_handler import init_database, get_system_stats
from routes.detect import register_detect_routes
from routes.history import register_history_routes
from routes.report import register_report_routes

import os

app = Flask(__name__)

# 从环境变量读取配置，如果没有则使用默认值
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# 配置
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 200 * 1024 * 1024))  # 限制上传文件大小为200MB
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['REQUEST_TIMEOUT'] = int(os.environ.get('REQUEST_TIMEOUT', 600))  # 10分钟超时（大文件需要更长时间）

# 生产环境配置
if os.environ.get('FLASK_ENV') == 'production':
    app.config['DEBUG'] = False
else:
    app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# 全局检测分析器
analyzer = None

# 错误处理
@app.errorhandler(413)
def request_entity_too_large(error):
    """处理文件过大错误"""
    return jsonify({
        'success': False,
        'error': '文件过大，最大支持200MB'
    }), 413

@app.errorhandler(400)
def bad_request(error):
    """处理请求错误"""
    return jsonify({
        'success': False,
        'error': f'请求错误: {str(error)}'
    }), 400


def init_analyzer():
    """初始化检测分析器"""
    global analyzer
    try:
        analyzer = DetectionAnalyzer()
        if len(analyzer.predictor.models) == 0:
            return False, "未找到训练好的模型，请先运行 train_models.py"
        return True, f"已加载 {len(analyzer.predictor.models)} 个模型"
    except Exception as e:
        return False, f"初始化失败: {str(e)}"


def get_analyzer_status():
    """获取分析器状态"""
    global analyzer
    if analyzer is None:
        init_success, init_message = init_analyzer()
        return init_success, init_message
    return True, f"已加载 {len(analyzer.predictor.models)} 个模型"

# 页面路由
@app.route('/')
def index():
    """首页"""
    init_success, init_message = get_analyzer_status()
    return render_template('index.html', init_success=init_success, init_message=init_message)

@app.route('/detect')
def detect_page():
    """检测页面"""
    init_success, _ = get_analyzer_status()
    return render_template('detect.html', init_success=init_success)

@app.route('/history')
def history_page():
    """历史记录页面"""
    init_success, _ = get_analyzer_status()
    return render_template('history.html', init_success=init_success)


# 延迟注册路由（在analyzer初始化后）
def register_all_routes():
    """注册所有API路由"""
    # 获取全局analyzer
    global analyzer
    register_detect_routes(app, analyzer)
    register_history_routes(app, analyzer)
    register_report_routes(app, analyzer)


# 初始化
if __name__ == '__main__':
    # 创建必要的目录
    Path('reports').mkdir(exist_ok=True)
    Path('static').mkdir(exist_ok=True)
    Path('templates').mkdir(exist_ok=True)
    Path('uploads').mkdir(exist_ok=True)
    
    # 初始化数据库
    init_database()
    
    # 初始化分析器
    init_success, init_message = init_analyzer()
    
    # 注册所有路由
    register_all_routes()
    
    # 检查端口是否被占用，如果被占用则使用5001
    import socket
    port = 5000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
    except OSError:
        print(f"\n[警告] 端口 {port} 已被占用，改用端口 5001")
        port = 5001
    
    print("\n" + "="*80)
    print(" " * 20 + "磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统")
    print("="*80)
    print(f"\n系统状态: {init_message}")
    print(f"数据库: detection.db")
    print("\n启动Web服务器...")
    print(f"访问地址: http://127.0.0.1:{port}")
    print("\n按 Ctrl+C 停止服务器")
    print("="*80)
    
    # 从环境变量获取端口（云端平台会提供）
    port = int(os.environ.get('PORT', port))
    debug_mode = app.config['DEBUG']
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
