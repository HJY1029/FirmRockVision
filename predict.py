#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 预测接口
使用训练好的模型对新数据进行预测
"""

import pandas as pd
import numpy as np
import pickle
import warnings
from pathlib import Path
from data_preprocessing import DataPreprocessor

warnings.filterwarnings('ignore')


class IDSPredictor:
    """网络入侵检测系统预测器"""
    
    def __init__(self, models_dir='models', preprocessor_path='processed_data/preprocessor.pkl'):
        """
        初始化预测器
        
        Args:
            models_dir: 模型文件目录
            preprocessor_path: 预处理器文件路径
        """
        self.models_dir = Path(models_dir)
        self.models = {}
        self.preprocessor = None
        
        # 加载预处理器
        if Path(preprocessor_path).exists():
            self.preprocessor = DataPreprocessor.load(preprocessor_path)
        else:
            print(f"警告: 未找到预处理器文件 {preprocessor_path}")
        
        # 加载模型
        self._load_models()
    
    def _load_models(self):
        """加载所有模型"""
        if not self.models_dir.exists():
            print(f"警告: 模型目录不存在: {self.models_dir}")
            return
        
        # 加载二分类模型
        binary_models = list(self.models_dir.glob('*_binary.pkl'))
        for model_file in binary_models:
            model_name = model_file.stem.replace('_binary', '')
            try:
                with open(model_file, 'rb') as f:
                    self.models[f'{model_name}_binary'] = pickle.load(f)
                print(f"已加载模型: {model_name}_binary")
            except Exception as e:
                print(f"警告: 无法加载模型 {model_name}: {e}")
        
        # 加载多分类模型
        multi_models = list(self.models_dir.glob('*_Multi.pkl'))
        for model_file in multi_models:
            model_name = model_file.stem.replace('_Multi', '')
            try:
                with open(model_file, 'rb') as f:
                    self.models[f'{model_name}_multi'] = pickle.load(f)
                
                # 加载对应的编码器（如果存在单独文件）
                encoder_file = self.models_dir / f'{model_name}_Multi_encoder.pkl'
                if encoder_file.exists():
                    with open(encoder_file, 'rb') as f:
                        self.models[f'{model_name}_multi_encoder'] = pickle.load(f)
                
                print(f"已加载模型: {model_name}_multi")
            except Exception as e:
                print(f"警告: 无法加载模型 {model_name}: {e}")
        
        # 也尝试加载编码器文件（如果单独保存）
        encoder_files = list(self.models_dir.glob('*_encoder.pkl'))
        for encoder_file in encoder_files:
            model_name = encoder_file.stem.replace('_encoder', '').replace('_Multi', '')
            if f'{model_name}_multi_encoder' not in self.models:
                try:
                    with open(encoder_file, 'rb') as f:
                        self.models[f'{model_name}_multi_encoder'] = pickle.load(f)
                    print(f"已加载编码器: {model_name}_multi_encoder")
                except Exception as e:
                    print(f"警告: 无法加载编码器 {model_name}: {e}")
    
    def predict_binary(self, data, model_name=None, threshold=0.5):
        """
        二分类预测（正常 vs 攻击）
        
        Args:
            data: 输入数据（DataFrame或字典）
            model_name: 模型名称，如果为None则使用第一个可用模型
            threshold: 预测阈值，攻击概率 >= threshold 时预测为攻击（默认0.5）
            
        Returns:
            预测结果字典
        """
        if self.preprocessor is None:
            raise ValueError("预处理器未加载")
        
        # 转换输入数据
        if isinstance(data, dict):
            data = pd.DataFrame([data])
        elif not isinstance(data, pd.DataFrame):
            raise ValueError("输入数据必须是DataFrame或字典")
        
        # 预处理
        try:
            X = self.preprocessor.transform(data)
            # 调试信息（仅前几个样本）
            if len(data) <= 5:
                print(f"\n[预测调试] 预处理信息:")
                print(f"  输入数据形状: {data.shape}")
                print(f"  输出数据形状: {X.shape}")
                if 'proto' in data.columns:
                    print(f"  输入proto值: {data['proto'].head(3).tolist()}")
                if 'state' in data.columns:
                    print(f"  输入state值: {data['state'].head(3).tolist()}")
        except Exception as e:
            print(f"[预测错误] 预处理失败: {e}")
            print(f"  数据列: {list(data.columns)[:10]}")
            raise
        
        # 选择模型
        if model_name is None:
            binary_models = [k for k in self.models.keys() if 'binary' in k]
            if len(binary_models) == 0:
                raise ValueError("没有可用的二分类模型")
            model_name = binary_models[0]
        
        if model_name not in self.models:
            raise ValueError(f"模型 {model_name} 不存在")
        
        model = self.models[model_name]
        
        # 预测概率
        y_pred_proba = None
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X)
        else:
            # 如果没有predict_proba，使用predict
            y_pred = model.predict(X)
            y_pred_proba = None
        
        # 根据阈值进行预测（如果使用概率）
        if y_pred_proba is not None:
            attack_probs = y_pred_proba[:, 1] if y_pred_proba.shape[1] > 1 else y_pred_proba[:, 0]
            # 使用阈值进行预测
            y_pred = (attack_probs >= threshold).astype(int)
            
            # 详细的调试信息
            print(f"\n[预测调试] 使用阈值: {threshold}")
            print(f"  攻击概率范围: [{attack_probs.min():.4f}, {attack_probs.max():.4f}]")
            print(f"  攻击概率均值: {attack_probs.mean():.4f}")
            print(f"  攻击概率中位数: {np.median(attack_probs):.4f}")
            print(f"  预测为攻击的数量 (阈值={threshold}): {(y_pred == 1).sum()}/{len(y_pred)}")
            
            # 显示不同阈值下的预测结果
            for t in [0.1, 0.2, 0.3, 0.4, 0.5]:
                count = (attack_probs >= t).sum()
                print(f"  阈值={t}: {count} 个攻击样本 ({count/len(attack_probs)*100:.1f}%)")
        else:
            # 使用默认预测
            y_pred = model.predict(X)
            print(f"\n[预测调试] 使用模型默认预测")
            print(f"  预测为攻击的数量: {(y_pred == 1).sum()}/{len(y_pred)}")
        
        results = []
        for i in range(len(y_pred)):
            result = {
                'prediction': '攻击' if y_pred[i] == 1 else '正常',
                'label': int(y_pred[i])
            }
            if y_pred_proba is not None:
                result['probability_normal'] = float(y_pred_proba[i][0])
                result['probability_attack'] = float(y_pred_proba[i][1])
                result['confidence'] = float(max(y_pred_proba[i]))
            
            results.append(result)
        
        return results if len(results) > 1 else results[0]
    
    def predict_multiclass(self, data, model_name=None):
        """
        多分类预测（攻击类型）
        
        Args:
            data: 输入数据（DataFrame或字典）
            model_name: 模型名称，如果为None则使用第一个可用模型
            
        Returns:
            预测结果字典
        """
        if self.preprocessor is None:
            raise ValueError("预处理器未加载")
        
        # 转换输入数据
        if isinstance(data, dict):
            data = pd.DataFrame([data])
        elif not isinstance(data, pd.DataFrame):
            raise ValueError("输入数据必须是DataFrame或字典")
        
        # 预处理
        X = self.preprocessor.transform(data)
        
        # 选择模型
        if model_name is None:
            multi_models = [k for k in self.models.keys() if 'multi' in k and 'encoder' not in k]
            if len(multi_models) == 0:
                raise ValueError("没有可用的多分类模型")
            model_name = multi_models[0]
        
        if model_name not in self.models:
            raise ValueError(f"模型 {model_name} 不存在")
        
        model = self.models[model_name]
        # 尝试获取编码器（可能的名字格式）
        encoder = self.models.get(f'{model_name}_encoder') or \
                  self.models.get(f'{model_name}_multi_encoder')
        
        # 预测
        y_pred_encoded = model.predict(X)
        y_pred_proba = None
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X)
        
        # 解码
        if encoder is not None:
            y_pred = encoder.inverse_transform(y_pred_encoded)
        else:
            y_pred = y_pred_encoded
        
        results = []
        for i in range(len(y_pred)):
            result = {
                'attack_type': str(y_pred[i]),
                'label': int(y_pred_encoded[i])
            }
            if y_pred_proba is not None:
                result['probabilities'] = {
                    encoder.classes_[j]: float(y_pred_proba[i][j])
                    for j in range(len(encoder.classes_))
                } if encoder is not None else {}
                result['confidence'] = float(max(y_pred_proba[i]))
            
            results.append(result)
        
        return results if len(results) > 1 else results[0]
    
    def predict(self, data, model_name=None, threshold=0.5):
        """
        完整预测流程（先二分类，如果是攻击则进行多分类）
        
        Args:
            data: 输入数据
            model_name: 模型名称前缀（如'RandomForest'）
            threshold: 预测阈值，攻击概率 >= threshold 时预测为攻击（默认0.5）
            
        Returns:
            预测结果字典
        """
        # 二分类预测
        binary_result = self.predict_binary(data, 
                                           model_name=f'{model_name}_binary' if model_name else None,
                                           threshold=threshold)
        
        if isinstance(binary_result, list):
            # 批量预测
            results = []
            for i, br in enumerate(binary_result):
                result = br.copy()
                if br['label'] == 1:  # 如果是攻击
                    # 多分类预测
                    if isinstance(data, pd.DataFrame):
                        multi_result = self.predict_multiclass(data.iloc[i:i+1], 
                                                             model_name=f'{model_name}_multi' if model_name else None)
                    else:
                        multi_result = self.predict_multiclass(data, 
                                                             model_name=f'{model_name}_multi' if model_name else None)
                    result.update(multi_result)
                results.append(result)
            return results
        else:
            # 单样本预测
            result = binary_result.copy()
            if binary_result['label'] == 1:  # 如果是攻击
                multi_result = self.predict_multiclass(data, 
                                                     model_name=f'{model_name}_multi' if model_name else None)
                result.update(multi_result)
            return result


def main():
    """主函数 - 示例用法"""
    print("\n" + "="*80)
    print(" " * 15 + "磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 预测接口")
    print("="*80)
    
    # 创建预测器
    predictor = IDSPredictor()
    
    if len(predictor.models) == 0:
        print("\n错误: 没有可用的模型，请先运行 train_models.py")
        return
    
    print(f"\n已加载 {len(predictor.models)} 个模型")
    
    # 示例：从测试集中取一个样本进行预测
    test_data_path = Path('UNSW_NB15_testing-set.csv')
    if test_data_path.exists():
        print("\n从测试集加载示例数据进行预测...")
        test_df = pd.read_csv(test_data_path, nrows=5)
        
        for idx, row in test_df.iterrows():
            print(f"\n{'='*80}")
            print(f"样本 {idx + 1}")
            print(f"{'='*80}")
            
            # 预测
            result = predictor.predict(row)
            
            # 显示结果
            print(f"\n预测结果:")
            print(f"  类型: {result['prediction']}")
            if 'probability_attack' in result:
                print(f"  置信度: {result['confidence']:.4f}")
                print(f"  正常概率: {result['probability_normal']:.4f}")
                print(f"  攻击概率: {result['probability_attack']:.4f}")
            
            if 'attack_type' in result:
                print(f"  攻击类型: {result['attack_type']}")
            
            # 实际标签
            if 'label' in row:
                actual = '攻击' if row['label'] == 1 else '正常'
                print(f"  实际标签: {actual}")
                if 'attack_cat' in row:
                    print(f"  实际攻击类型: {row['attack_cat']}")
    else:
        print("\n未找到测试数据文件，无法进行示例预测")
        print("\n使用示例:")
        print("""
        from predict import IDSPredictor
        
        predictor = IDSPredictor()
        
        # 单样本预测
        sample = {
            'sttl': 254,
            'sbytes': 496,
            'ct_state_ttl': 2,
            # ... 其他特征
        }
        result = predictor.predict(sample)
        print(result)
        """)


if __name__ == "__main__":
    main()

