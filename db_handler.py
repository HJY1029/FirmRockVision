#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库操作模块
处理所有数据库相关的操作
"""

import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import time
import numpy as np

DB_PATH = Path('detection.db')


def init_database():
    """初始化数据库"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 创建上传文件表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_size INTEGER,
            upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            row_count INTEGER,
            status TEXT DEFAULT 'pending'
        )
    ''')
    
    # 创建检测结果表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            sample_index INTEGER,
            detection_type TEXT,
            attack_type TEXT,
            threat_score REAL,
            threat_level TEXT,
            confidence REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            result_data TEXT,
            FOREIGN KEY (file_id) REFERENCES uploaded_files(id)
        )
    ''')
    
    # 创建索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_id ON detection_results(file_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON detection_results(timestamp)')
    
    conn.commit()
    conn.close()
    print(f"数据库初始化完成: {DB_PATH}")


def save_uploaded_file(filename: str, file_size: int, row_count: int, status: str = 'processing') -> int:
    """保存上传文件信息，返回文件ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO uploaded_files (filename, file_size, row_count, status)
        VALUES (?, ?, ?, ?)
    ''', (filename, file_size, row_count, status))
    file_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return file_id


def update_file_status(file_id: int, status: str):
    """更新文件状态"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE uploaded_files SET status = ? WHERE id = ?
    ''', (status, file_id))
    conn.commit()
    conn.close()


def save_detection_result(file_id: Optional[int], sample_index: int, result: Dict) -> bool:
    """保存单个检测结果到数据库"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # 使用本地时间戳（确保使用系统本地时间）
        local_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        cursor.execute('''
            INSERT INTO detection_results 
            (file_id, sample_index, detection_type, attack_type, threat_score, 
             threat_level, confidence, timestamp, result_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            file_id,
            sample_index,
            result['prediction']['type'],
            result['prediction'].get('attack_type'),
            result['threat_analysis']['threat_score'],
            result['threat_analysis']['threat_level'],
            result['prediction']['confidence'],
            local_timestamp,
            json.dumps(result, ensure_ascii=False, default=str)
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"保存检测结果失败: {e}")
        return False


def save_batch_detection_results(file_id: int, results: List[Dict]) -> int:
    """批量保存检测结果，返回成功保存的数量"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    saved_count = 0
    # 使用本地时间戳（所有记录使用相同时间戳，表示同一批检测）
    # 使用 time.localtime() 确保获取系统本地时间
    local_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    
    for idx, result in enumerate(results):
        try:
            cursor.execute('''
                INSERT INTO detection_results 
                (file_id, sample_index, detection_type, attack_type, threat_score, 
                 threat_level, confidence, timestamp, result_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_id,
                idx,
                result['prediction']['type'],
                result['prediction'].get('attack_type'),
                result['threat_analysis']['threat_score'],
                result['threat_analysis']['threat_level'],
                result['prediction']['confidence'],
                local_timestamp,
                json.dumps(result, ensure_ascii=False, default=str)
            ))
            saved_count += 1
        except Exception as e:
            print(f"保存检测结果 {idx} 失败: {e}")
            continue
    
    conn.commit()
    conn.close()
    return saved_count


def get_detection_history(days: Optional[int] = None, limit: int = 1000) -> Tuple[List[Dict], Dict]:
    """获取检测历史记录和统计信息"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 构建查询条件 - 按时间戳和ID双重排序，确保最新记录在最前面
    if days:
        cursor.execute('''
            SELECT id, file_id, sample_index, detection_type, attack_type, 
                   threat_score, threat_level, confidence, timestamp, result_data
            FROM detection_results
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        ''', (days, limit))
    else:
        cursor.execute('''
            SELECT id, file_id, sample_index, detection_type, attack_type, 
                   threat_score, threat_level, confidence, timestamp, result_data
            FROM detection_results
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        ''', (limit,))
    
    rows = cursor.fetchall()
    
    # 转换为字典格式
    recent_records = []
    for row in rows:
        result_data = json.loads(row[9]) if row[9] else {}
        record = {
            'id': row[0],
            'file_id': row[1],
            'sample_index': row[2],
            'timestamp': row[8],
            'prediction': {
                'type': row[3] or '未知',
                'label': 1 if row[3] == '攻击' else 0,
                'attack_type': row[4],
                'confidence': row[7] or 0.0
            },
            'threat_analysis': {
                'threat_score': row[5] or 0.0,
                'threat_level': row[6] or '正常'
            }
        }
        # 合并result_data中的信息
        if result_data and isinstance(result_data, dict):
            if 'prediction' in result_data:
                record['prediction'].update(result_data['prediction'])
            if 'threat_analysis' in result_data:
                record['threat_analysis'].update(result_data['threat_analysis'])
        recent_records.append(record)
    
    # 统计分析
    total = len(recent_records)
    attacks = sum(1 for r in recent_records if r['prediction']['label'] == 1)
    normal = total - attacks
    
    attack_types = {}
    threat_levels = {}
    threat_scores = []
    
    for r in recent_records:
        if r['prediction']['label'] == 1:
            attack_type = r['prediction'].get('attack_type', 'Unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        threat_level = r['threat_analysis'].get('threat_level', '正常')
        threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
        
        threat_score = r['threat_analysis'].get('threat_score', 0)
        threat_scores.append(threat_score)
    
    # 计算统计信息
    analysis = {
        'period': f'最近{days}天' if days else '全部',
        'total_detections': total,
        'normal_count': normal,
        'attack_count': attacks,
        'attack_rate': round(attacks / total * 100, 2) if total > 0 else 0,
        'attack_type_distribution': attack_types,
        'threat_level_distribution': threat_levels,
        'threat_score_stats': {
            'mean': round(np.mean(threat_scores), 2) if threat_scores else 0,
            'max': round(max(threat_scores), 2) if threat_scores else 0,
            'min': round(min(threat_scores), 2) if threat_scores else 0,
            'std': round(np.std(threat_scores), 2) if threat_scores else 0
        }
    }
    
    if total == 0:
        analysis['message'] = f'最近{days}天内无检测记录' if days else '暂无检测历史记录'
    
    conn.close()
    return recent_records, analysis


def get_uploaded_files(limit: int = 50) -> List[Dict]:
    """获取上传文件列表"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, filename, file_size, upload_time, row_count, status
        FROM uploaded_files
        ORDER BY upload_time DESC
        LIMIT ?
    ''', (limit,))
    
    files = []
    for row in cursor.fetchall():
        files.append({
            'id': row[0],
            'filename': row[1],
            'file_size': row[2],
            'upload_time': row[3],
            'row_count': row[4],
            'status': row[5]
        })
    
    conn.close()
    return files


def get_file_results(file_id: int) -> List[Dict]:
    """获取指定文件的检测结果"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT sample_index, detection_type, attack_type, threat_score, 
               threat_level, confidence, timestamp, result_data
        FROM detection_results
        WHERE file_id = ?
        ORDER BY sample_index
    ''', (file_id,))
    
    results = []
    for row in cursor.fetchall():
        results.append({
            'sample_index': row[0],
            'detection_type': row[1],
            'attack_type': row[2],
            'threat_score': row[3],
            'threat_level': row[4],
            'confidence': row[5],
            'timestamp': row[6],
            'result_data': json.loads(row[7]) if row[7] else None
        })
    
    conn.close()
    return results


def get_detection_result_by_id(result_id: int) -> Optional[Dict]:
    """根据ID获取单条检测结果的完整信息"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, file_id, sample_index, detection_type, attack_type, 
               threat_score, threat_level, confidence, timestamp, result_data
        FROM detection_results
        WHERE id = ?
    ''', (result_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    # 解析完整结果数据
    result_data = json.loads(row[9]) if row[9] else {}
    
    # 构建完整结果
    result = {
        'id': row[0],
        'file_id': row[1],
        'sample_index': row[2],
        'timestamp': row[8],
        'prediction': {
            'type': row[3] or '未知',
            'label': 1 if row[3] == '攻击' else 0,
            'attack_type': row[4],
            'confidence': row[7] or 0.0
        },
        'threat_analysis': {
            'threat_score': row[5] or 0.0,
            'threat_level': row[6] or '正常'
        }
    }
    
    # 合并result_data中的完整信息
    if result_data and isinstance(result_data, dict):
        if 'prediction' in result_data:
            result['prediction'].update(result_data['prediction'])
        if 'threat_analysis' in result_data:
            result['threat_analysis'].update(result_data['threat_analysis'])
        if 'attack_description' in result_data:
            result['attack_description'] = result_data['attack_description']
        if 'recommendations' in result_data:
            result['recommendations'] = result_data['recommendations']
        if 'sample_features' in result_data:
            result['sample_features'] = result_data['sample_features']
    
    return result


def get_system_stats() -> Dict:
    """获取系统统计信息"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM uploaded_files')
    total_files = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM detection_results')
    total_detections = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM uploaded_files WHERE status = ?', ('completed',))
    completed_files = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_files': total_files,
        'total_detections': total_detections,
        'completed_files': completed_files
    }

