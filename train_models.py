#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 模型训练模块
训练多个机器学习模型进行二分类（正常/攻击）和多分类（攻击类型）
"""

import pandas as pd
import numpy as np
import pickle
import time
import warnings
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings('ignore')

# 尝试导入XGBoost和LightGBM（可选）
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("警告: XGBoost未安装，将跳过XGBoost模型")

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("警告: LightGBM未安装，将跳过LightGBM模型")


class ModelTrainer:
    """模型训练器"""
    
    def __init__(self, random_state=42):
        self.random_state = random_state
        self.models = {}
        self.results = {}
        
    def train_binary_classification(self, X_train, y_train, X_test, y_test):
        """
        训练二分类模型（正常 vs 攻击）
        
        Args:
            X_train: 训练特征
            y_train: 训练标签 (0=正常, 1=攻击)
            X_test: 测试特征
            y_test: 测试标签
        """
        print("="*80)
        print("训练二分类模型（正常 vs 攻击）")
        print("="*80)
        
        # 定义模型
        models_config = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=self.random_state,
                n_jobs=-1,
                verbose=0
            ),
        }
        
        if HAS_XGBOOST:
            models_config['XGBoost'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=self.random_state,
                n_jobs=-1,
                eval_metric='logloss',
                verbosity=0
            )
        
        if HAS_LIGHTGBM:
            models_config['LightGBM'] = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=self.random_state,
                n_jobs=-1,
                verbose=-1
            )
        
        # 训练每个模型
        for model_name, model in models_config.items():
            print(f"\n{'='*80}")
            print(f"训练 {model_name}")
            print(f"{'='*80}")
            
            start_time = time.time()
            
            # 训练
            model.fit(X_train, y_train)
            train_time = time.time() - start_time
            
            # 预测
            start_time = time.time()
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            predict_time = time.time() - start_time
            
            # 评估
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='binary', zero_division=0)
            recall = recall_score(y_test, y_pred, average='binary', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='binary', zero_division=0)
            
            # ROC AUC
            roc_auc = None
            if y_pred_proba is not None:
                try:
                    roc_auc = roc_auc_score(y_test, y_pred_proba)
                except:
                    pass
            
            # 保存结果
            self.models[f'{model_name}_binary'] = model
            self.results[f'{model_name}_binary'] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'roc_auc': roc_auc,
                'train_time': train_time,
                'predict_time': predict_time,
                'y_pred': y_pred,
                'y_pred_proba': y_pred_proba,
                'confusion_matrix': confusion_matrix(y_test, y_pred)
            }
            
            # 打印结果
            print(f"\n训练时间: {train_time:.2f} 秒")
            print(f"预测时间: {predict_time:.2f} 秒")
            print(f"\n评估指标:")
            print(f"  准确率 (Accuracy):  {accuracy:.4f}")
            print(f"  精确率 (Precision): {precision:.4f}")
            print(f"  召回率 (Recall):    {recall:.4f}")
            print(f"  F1分数:             {f1:.4f}")
            if roc_auc:
                print(f"  ROC AUC:            {roc_auc:.4f}")
            
            print(f"\n混淆矩阵:")
            cm = confusion_matrix(y_test, y_pred)
            print(f"              预测")
            print(f"           正常  攻击")
            print(f"实际 正常  {cm[0,0]:5d} {cm[0,1]:5d}")
            print(f"     攻击  {cm[1,0]:5d} {cm[1,1]:5d}")
    
    def train_multiclass_classification(self, X_train, y_train, X_test, y_test, attack_cats_train, attack_cats_test):
        """
        训练多分类模型（攻击类型分类）
        
        Args:
            X_train: 训练特征
            y_train: 训练标签 (0=正常, 1=攻击)
            X_test: 测试特征
            y_test: 测试标签
            attack_cats_train: 训练集攻击类型标签
            attack_cats_test: 测试集攻击类型标签
        """
        print("\n" + "="*80)
        print("训练多分类模型（攻击类型分类）")
        print("="*80)
        
        # 转换为Series（如果还不是）
        if not isinstance(attack_cats_train, pd.Series):
            attack_cats_train = pd.Series(attack_cats_train)
        if not isinstance(attack_cats_test, pd.Series):
            attack_cats_test = pd.Series(attack_cats_test)
        
        # 只使用攻击样本进行多分类
        attack_mask_train = y_train == 1
        attack_mask_test = y_test == 1
        
        if attack_mask_train.sum() == 0 or attack_mask_test.sum() == 0:
            print("警告: 没有足够的攻击样本进行多分类训练")
            return
        
        X_train_attack = X_train[attack_mask_train]
        y_train_attack = attack_cats_train[attack_mask_train]
        X_test_attack = X_test[attack_mask_test]
        y_test_attack = attack_cats_test[attack_mask_test]
        
        print(f"\n攻击样本数:")
        print(f"  训练集: {len(X_train_attack):,}")
        print(f"  测试集: {len(X_test_attack):,}")
        
        # 编码攻击类型
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        y_train_encoded = le.fit_transform(y_train_attack)
        y_test_encoded = le.transform(y_test_attack)
        
        attack_types = le.classes_
        print(f"\n攻击类型 ({len(attack_types)} 种):")
        for i, atype in enumerate(attack_types):
            count_train = (y_train_attack == atype).sum()
            count_test = (y_test_attack == atype).sum()
            print(f"  {i+1}. {atype:<20} 训练: {count_train:>6,}  测试: {count_test:>6,}")
        
        # 定义模型
        models_config = {
            'RandomForest_Multi': RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=self.random_state,
                n_jobs=-1,
                verbose=0
            ),
        }
        
        if HAS_XGBOOST:
            models_config['XGBoost_Multi'] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=self.random_state,
                n_jobs=-1,
                eval_metric='mlogloss',
                verbosity=0
            )
        
        if HAS_LIGHTGBM:
            models_config['LightGBM_Multi'] = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=self.random_state,
                n_jobs=-1,
                verbose=-1
            )
        
        # 训练每个模型
        for model_name, model in models_config.items():
            print(f"\n{'='*80}")
            print(f"训练 {model_name}")
            print(f"{'='*80}")
            
            start_time = time.time()
            model.fit(X_train_attack, y_train_encoded)
            train_time = time.time() - start_time
            
            start_time = time.time()
            y_pred = model.predict(X_test_attack)
            predict_time = time.time() - start_time
            
            # 评估
            accuracy = accuracy_score(y_test_encoded, y_pred)
            precision = precision_score(y_test_encoded, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test_encoded, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test_encoded, y_pred, average='weighted', zero_division=0)
            
            # 保存结果
            self.models[f'{model_name}'] = model
            self.models[f'{model_name}_encoder'] = le
            self.results[f'{model_name}'] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'train_time': train_time,
                'predict_time': predict_time,
                'y_pred': y_pred,
                'y_test': y_test_encoded,
                'attack_types': attack_types,
                'confusion_matrix': confusion_matrix(y_test_encoded, y_pred)
            }
            
            print(f"\n训练时间: {train_time:.2f} 秒")
            print(f"预测时间: {predict_time:.2f} 秒")
            print(f"\n评估指标:")
            print(f"  准确率 (Accuracy):  {accuracy:.4f}")
            print(f"  精确率 (Precision): {precision:.4f}")
            print(f"  召回率 (Recall):    {recall:.4f}")
            print(f"  F1分数:             {f1:.4f}")
            
            print(f"\n分类报告:")
            print(classification_report(
                y_test_encoded, y_pred,
                target_names=attack_types,
                zero_division=0
            ))
    
    def save_models(self, output_dir='models'):
        """保存所有模型"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"\n保存模型到: {output_path.absolute()}")
        
        for model_name, model in self.models.items():
            filepath = output_path / f'{model_name}.pkl'
            with open(filepath, 'wb') as f:
                pickle.dump(model, f)
            print(f"  已保存: {filepath}")
    
    def save_results(self, output_dir='results'):
        """保存结果"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"\n保存结果到: {output_path.absolute()}")
        
        # 保存评估指标
        results_summary = []
        for model_name, result in self.results.items():
            results_summary.append({
                'Model': model_name,
                'Accuracy': result['accuracy'],
                'Precision': result['precision'],
                'Recall': result['recall'],
                'F1': result['f1'],
                'ROC_AUC': result.get('roc_auc', None),
                'Train_Time': result['train_time'],
                'Predict_Time': result['predict_time']
            })
        
        results_df = pd.DataFrame(results_summary)
        results_df.to_csv(output_path / 'model_comparison.csv', index=False)
        print(f"  已保存: {output_path / 'model_comparison.csv'}")
        
        return results_df


def main():
    """主函数"""
    print("\n" + "="*80)
    print(" " * 15 + "磐石之眼（FirmRock Vision）- 模型训练")
    print("="*80)
    
    # 加载预处理后的数据
    data_dir = Path('processed_data')
    
    if not data_dir.exists():
        print("错误: 未找到预处理数据，请先运行 data_preprocessing.py")
        return
    
    print("\n加载预处理后的数据...")
    X_train = pd.read_csv(data_dir / 'X_train.csv')
    y_train = pd.read_csv(data_dir / 'y_train.csv').values.ravel()
    X_test = pd.read_csv(data_dir / 'X_test.csv')
    y_test = pd.read_csv(data_dir / 'y_test.csv').values.ravel()
    
    print(f"训练集: {X_train.shape}")
    print(f"测试集: {X_test.shape}")
    
    # 加载攻击类型（如果存在）
    attack_cats_train = None
    attack_cats_test = None
    if (data_dir / 'attack_cat_train.csv').exists():
        attack_cats_train = pd.read_csv(data_dir / 'attack_cat_train.csv').values.ravel()
        attack_cats_test = pd.read_csv(data_dir / 'attack_cat_test.csv').values.ravel()
        print(f"攻击类型标签已加载")
    
    # 创建训练器
    trainer = ModelTrainer(random_state=42)
    
    # 训练二分类模型
    trainer.train_binary_classification(X_train, y_train, X_test, y_test)
    
    # 训练多分类模型（如果有攻击类型标签）
    if attack_cats_train is not None:
        trainer.train_multiclass_classification(
            X_train, y_train, X_test, y_test,
            pd.Series(attack_cats_train), pd.Series(attack_cats_test)
        )
    
    # 保存模型和结果
    trainer.save_models()
    results_df = trainer.save_results()
    
    # 打印模型对比
    print("\n" + "="*80)
    print("模型对比总结")
    print("="*80)
    print(results_df.to_string(index=False))
    
    print("\n" + "="*80)
    print("模型训练完成!")
    print("="*80)


if __name__ == "__main__":
    main()

