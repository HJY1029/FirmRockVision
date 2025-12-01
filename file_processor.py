#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件处理模块
处理CSV文件的上传、读取和格式转换
"""

import pandas as pd
import chardet
from typing import Tuple, Optional, Dict
from pathlib import Path

# UNSW-NB15原始数据列名（49个特征）
UNSW_COLUMN_NAMES = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 
    'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
    'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smean', 'dmean', 'trans_depth', 'response_body_len', 'sjit', 'djit',
    'Stime', 'Ltime', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
]

# 需要的30个特征
REQUIRED_FEATURES = [
    'sttl', 'sbytes', 'ct_state_ttl', 'sload', 'smean', 'dttl', 'dbytes',
    'dmean', 'dur', 'dload', 'dinpkt', 'dpkts', 'state', 'sinpkt',
    'ct_dst_sport_ltm', 'spkts', 'ct_src_dport_ltm', 'swin', 'dwin',
    'ct_dst_src_ltm', 'djit', 'sjit', 'ct_dst_ltm', 'dloss', 'ct_srv_dst',
    'ct_src_ltm', 'sloss', 'ct_srv_src', 'proto', 'dtcpb'
]


def detect_file_encoding(file_content: bytes) -> Optional[str]:
    """检测文件编码"""
    try:
        encoding_result = chardet.detect(file_content)
        detected_encoding = encoding_result.get('encoding', 'utf-8')
        confidence = encoding_result.get('confidence', 0)
        
        if confidence < 0.7:
            return None
        return detected_encoding
    except Exception:
        return None


def read_csv_file(file, encoding: Optional[str] = None) -> Tuple[pd.DataFrame, str, list]:
    """
    读取CSV文件，自动处理编码和格式
    
    Returns:
        (DataFrame, encoding_used, encoding_errors)
    """
    encodings_to_try = []
    if encoding:
        encodings_to_try.append(encoding)
    encodings_to_try.extend(['utf-8', 'gbk', 'gb2312', 'gb18030', 'big5', 
                             'latin1', 'iso-8859-1', 'windows-1252', 'cp936'])
    encodings_to_try = list(dict.fromkeys(encodings_to_try))
    
    encoding_errors = []
    df = None
    encoding_used = None
    
    for enc in encodings_to_try:
        try:
            file.seek(0)
            # 先读取一行检查列数
            test_df = pd.read_csv(file, encoding=enc, header=None, nrows=1)
            
            if len(test_df.columns) == 49:
                # 可能是UNSW-NB15原始格式
                file.seek(0)
                df = pd.read_csv(file, encoding=enc, header=None, names=UNSW_COLUMN_NAMES)
                encoding_used = enc
                print(f"成功使用编码 {enc} 读取文件，已设置UNSW-NB15列名")
                break
            else:
                # 尝试正常读取（有列名）
                file.seek(0)
                df = pd.read_csv(file, encoding=enc)
                encoding_used = enc
                print(f"成功使用编码 {enc} 读取文件")
                break
        except UnicodeDecodeError as e:
            encoding_errors.append(f"{enc}: {str(e)}")
            continue
        except Exception as e:
            encoding_errors.append(f"{enc}: {str(e)}")
            continue
    
    if df is None:
        error_msg = f'CSV文件读取失败，已尝试的编码: {", ".join(encodings_to_try[:5])}'
        if encoding_errors:
            error_msg += f'\n错误详情: {encoding_errors[0]}'
        raise ValueError(error_msg)
    
    return df, encoding_used, encoding_errors


def extract_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    从数据框中提取需要的30个特征
    
    Returns:
        (DataFrame, error_message)
    """
    # 检查列名，如果是UNSW-NB15原始格式，提取需要的特征
    if len(df.columns) == 49 and all(col in UNSW_COLUMN_NAMES for col in df.columns):
        # 原始UNSW-NB15格式，提取需要的30个特征
        print("检测到UNSW-NB15原始数据格式，提取30个特征...")
        try:
            df = df[REQUIRED_FEATURES].copy()
            print(f"成功提取 {len(df.columns)} 个特征")
            return df, None
        except KeyError as e:
            missing = [f for f in REQUIRED_FEATURES if f not in df.columns]
            return None, f'UNSW-NB15数据缺少特征: {", ".join(missing)}'
    elif all(f in df.columns for f in REQUIRED_FEATURES):
        # 已经有需要的特征，直接使用
        df = df[REQUIRED_FEATURES].copy()
        print(f"使用现有特征列，共 {len(df.columns)} 个特征")
        return df, None
    else:
        # 检查缺少的特征
        missing_features = [f for f in REQUIRED_FEATURES if f not in df.columns]
        available_features = list(df.columns)
        
        # 检查是否是标签文件
        is_label_file = False
        label_file_indicators = ['attack_cat', 'label', 'y_']
        if any(indicator in str(available_features).lower() for indicator in label_file_indicators):
            if len(available_features) <= 2:
                is_label_file = True
        
        error_msg = f'CSV文件缺少必要的特征列: {", ".join(missing_features)}'
        if is_label_file:
            error_msg += '\n\n❌ 您上传的是标签文件（如attack_cat_test.csv, y_test.csv），不是特征数据文件。\n'
            error_msg += '✅ 请上传包含30个特征列的文件，例如：\n'
            error_msg += '   - UNSW-NB15_1.csv（原始数据，49列，系统会自动提取特征）\n'
            error_msg += '   - X_test.csv 或 X_train.csv（已处理的特征数据，30列）'
        else:
            error_msg += f'\n\n文件包含的列 ({len(available_features)}个): {", ".join(available_features[:15])}'
            if len(available_features) > 15:
                error_msg += '...'
            error_msg += f'\n\n需要的列 ({len(REQUIRED_FEATURES)}个): {", ".join(REQUIRED_FEATURES[:10])}...'
        
        return None, error_msg


def validate_features(df: pd.DataFrame) -> Optional[str]:
    """验证数据框是否包含必要的特征"""
    required_features = ['sttl', 'sbytes', 'ct_state_ttl']
    missing_features = [f for f in required_features if f not in df.columns]
    if missing_features:
        return f'CSV文件缺少必要的特征列: {", ".join(missing_features)}'
    return None

