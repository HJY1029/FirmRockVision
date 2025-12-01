#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 数据预处理模块
使用特征选择结果进行数据清洗和特征工程
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import warnings
from pathlib import Path

warnings.filterwarnings('ignore')

# 从特征选择结果中获取的30个重要特征
SELECTED_FEATURES = [
    'sttl',
    'sbytes',
    'ct_state_ttl',
    'sload',
    'smean',
    'dttl',
    'dbytes',
    'dmean',
    'dur',
    'dload',
    'dinpkt',
    'dpkts',
    'state',
    'sinpkt',
    'ct_dst_sport_ltm',
    'spkts',
    'ct_src_dport_ltm',
    'swin',
    'dwin',
    'ct_dst_src_ltm',
    'djit',
    'sjit',
    'ct_dst_ltm',
    'dloss',
    'ct_srv_dst',
    'ct_src_ltm',
    'sloss',
    'ct_srv_src',
    'proto',
    'dtcpb',
]

# 分类特征
CATEGORICAL_FEATURES = ['proto', 'state']

# 数值特征（从SELECTED_FEATURES中排除分类特征）
NUMERICAL_FEATURES = [f for f in SELECTED_FEATURES if f not in CATEGORICAL_FEATURES]


class DataPreprocessor:
    """数据预处理器"""
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_fitted = False
        
    def fit_transform(self, df, target_col='label'):
        """
        拟合并转换数据
        
        Args:
            df: 输入数据框
            target_col: 目标列名
            
        Returns:
            处理后的特征矩阵和标签
        """
        print("="*80)
        print("数据预处理 - 拟合和转换")
        print("="*80)
        
        # 提取特征和标签
        X = df[SELECTED_FEATURES].copy()
        y = df[target_col].copy()
        
        print(f"\n原始数据形状: {df.shape}")
        print(f"使用特征数: {len(SELECTED_FEATURES)}")
        print(f"样本数: {len(X)}")
        
        # 处理缺失值
        print("\n处理缺失值...")
        missing_before = X.isnull().sum().sum()
        if missing_before > 0:
            print(f"  缺失值总数: {missing_before}")
            
            # 数值特征用中位数填充
            for col in NUMERICAL_FEATURES:
                if col in X.columns:
                    median_val = X[col].median()
                    X[col] = X[col].fillna(median_val)
            
            # 分类特征用众数填充
            for col in CATEGORICAL_FEATURES:
                if col in X.columns:
                    mode_val = X[col].mode()[0] if len(X[col].mode()) > 0 else 0
                    X[col] = X[col].fillna(mode_val)
        
        missing_after = X.isnull().sum().sum()
        print(f"  处理后缺失值: {missing_after}")
        
        # 编码分类特征
        print("\n编码分类特征...")
        for col in CATEGORICAL_FEATURES:
            if col in X.columns:
                le = LabelEncoder()
                X[col] = le.fit_transform(X[col].astype(str))
                self.label_encoders[col] = le
                print(f"  {col}: {len(le.classes_)} 个类别")
        
        # 标准化数值特征
        print("\n标准化数值特征...")
        X_numerical = X[NUMERICAL_FEATURES]
        X_numerical_scaled = self.scaler.fit_transform(X_numerical)
        X[NUMERICAL_FEATURES] = X_numerical_scaled
        
        self.is_fitted = True
        
        print(f"\n预处理完成!")
        print(f"  最终特征形状: {X.shape}")
        print(f"  标签分布:")
        print(f"    Normal (0): {(y == 0).sum():,} ({(y == 0).mean()*100:.2f}%)")
        print(f"    Attack (1): {(y == 1).sum():,} ({(y == 1).mean()*100:.2f}%)")
        
        return X, y
    
    def transform(self, df):
        """
        转换新数据（使用已拟合的转换器）
        
        Args:
            df: 输入数据框
            
        Returns:
            处理后的特征矩阵
        """
        if not self.is_fitted:
            raise ValueError("预处理器尚未拟合，请先调用 fit_transform")
        
        X = df[SELECTED_FEATURES].copy()
        
        # 处理缺失值
        for col in NUMERICAL_FEATURES:
            if col in X.columns:
                median_val = X[col].median()
                X[col] = X[col].fillna(median_val)
        
        for col in CATEGORICAL_FEATURES:
            if col in X.columns:
                mode_val = X[col].mode()[0] if len(X[col].mode()) > 0 else 0
                X[col] = X[col].fillna(mode_val)
        
        # 编码分类特征
        for col in CATEGORICAL_FEATURES:
            if col in X.columns and col in self.label_encoders:
                le = self.label_encoders[col]
                # 处理未见过的类别
                X[col] = X[col].astype(str)
                known_classes = set(le.classes_)
                X[col] = X[col].apply(lambda x: x if x in known_classes else le.classes_[0])
                X[col] = le.transform(X[col])
        
        # 标准化数值特征
        X_numerical = X[NUMERICAL_FEATURES]
        X_numerical_scaled = self.scaler.transform(X_numerical)
        X[NUMERICAL_FEATURES] = X_numerical_scaled
        
        return X
    
    def save(self, filepath):
        """保存预处理器"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'scaler': self.scaler,
                'label_encoders': self.label_encoders,
                'is_fitted': self.is_fitted
            }, f)
        print(f"预处理器已保存到: {filepath}")
    
    @classmethod
    def load(cls, filepath):
        """加载预处理器"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        preprocessor = cls()
        preprocessor.scaler = data['scaler']
        preprocessor.label_encoders = data['label_encoders']
        preprocessor.is_fitted = data['is_fitted']
        
        print(f"预处理器已从 {filepath} 加载")
        return preprocessor


def load_datasets(train_path='UNSW_NB15_training-set.csv', 
                  test_path='UNSW_NB15_testing-set.csv'):
    """加载训练集和测试集"""
    print("加载数据集...")
    
    train_df = pd.read_csv(train_path, low_memory=False)
    test_df = pd.read_csv(test_path, low_memory=False)
    
    print(f"训练集: {len(train_df):,} 条记录")
    print(f"测试集: {len(test_df):,} 条记录")
    
    return train_df, test_df


def main():
    """主函数"""
    print("\n" + "="*80)
    print(" " * 15 + "磐石之眼（FirmRock Vision）- 数据预处理")
    print("="*80)
    
    # 加载数据
    train_df, test_df = load_datasets()
    
    # 创建预处理器
    preprocessor = DataPreprocessor(random_state=42)
    
    # 处理训练集
    print("\n" + "-"*80)
    print("处理训练集")
    print("-"*80)
    X_train, y_train = preprocessor.fit_transform(train_df)
    
    # 处理测试集
    print("\n" + "-"*80)
    print("处理测试集")
    print("-"*80)
    X_test = preprocessor.transform(test_df)
    y_test = test_df['label'].copy()
    
    # 保存预处理后的数据
    output_dir = Path('processed_data')
    output_dir.mkdir(exist_ok=True)
    
    print("\n" + "-"*80)
    print("保存预处理结果")
    print("-"*80)
    
    # 保存为CSV
    X_train.to_csv(output_dir / 'X_train.csv', index=False)
    y_train.to_csv(output_dir / 'y_train.csv', index=False)
    X_test.to_csv(output_dir / 'X_test.csv', index=False)
    y_test.to_csv(output_dir / 'y_test.csv', index=False)
    
    print(f"  已保存: {output_dir / 'X_train.csv'}")
    print(f"  已保存: {output_dir / 'y_train.csv'}")
    print(f"  已保存: {output_dir / 'X_test.csv'}")
    print(f"  已保存: {output_dir / 'y_test.csv'}")
    
    # 保存预处理器
    preprocessor.save(output_dir / 'preprocessor.pkl')
    
    # 保存攻击类型信息（用于多分类任务）
    if 'attack_cat' in train_df.columns:
        attack_cats_train = train_df['attack_cat'].copy()
        attack_cats_test = test_df['attack_cat'].copy()
        attack_cats_train.to_csv(output_dir / 'attack_cat_train.csv', index=False)
        attack_cats_test.to_csv(output_dir / 'attack_cat_test.csv', index=False)
        print(f"  已保存: {output_dir / 'attack_cat_train.csv'}")
        print(f"  已保存: {output_dir / 'attack_cat_test.csv'}")
    
    print("\n" + "="*80)
    print("数据预处理完成!")
    print("="*80)
    print(f"\n输出目录: {output_dir.absolute()}")
    print(f"训练集: {X_train.shape[0]:,} 样本, {X_train.shape[1]} 特征")
    print(f"测试集: {X_test.shape[0]:,} 样本, {X_test.shape[1]} 特征")


if __name__ == "__main__":
    main()

