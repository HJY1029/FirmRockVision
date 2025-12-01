#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 使用示例
演示如何使用训练好的模型进行预测
"""

import pandas as pd
from predict import IDSPredictor
from pathlib import Path


def example_single_prediction():
    """示例1: 单样本预测"""
    print("="*80)
    print("示例1: 单样本预测")
    print("="*80)
    
    # 创建预测器
    predictor = IDSPredictor()
    
    # 准备一个样本（使用测试集中的真实数据）
    test_file = Path('UNSW_NB15_testing-set.csv')
    if not test_file.exists():
        print("警告: 未找到测试数据文件")
        return
    
    # 加载一个样本
    df = pd.read_csv(test_file, nrows=1)
    sample = df.iloc[0].to_dict()
    
    print(f"\n输入样本特征（部分）:")
    print(f"  sttl: {sample.get('sttl', 'N/A')}")
    print(f"  sbytes: {sample.get('sbytes', 'N/A')}")
    print(f"  dur: {sample.get('dur', 'N/A')}")
    
    # 预测
    result = predictor.predict(sample)
    
    # 显示结果
    print(f"\n预测结果:")
    print(f"  类型: {result['prediction']}")
    if 'confidence' in result:
        print(f"  置信度: {result['confidence']:.4f}")
        print(f"  正常概率: {result.get('probability_normal', 'N/A')}")
        print(f"  攻击概率: {result.get('probability_attack', 'N/A')}")
    
    if 'attack_type' in result:
        print(f"  攻击类型: {result['attack_type']}")
    
    # 实际标签（如果存在）
    if 'label' in sample:
        actual = '攻击' if sample['label'] == 1 else '正常'
        print(f"\n实际标签: {actual}")
        if 'attack_cat' in sample:
            print(f"实际攻击类型: {sample['attack_cat']}")


def example_batch_prediction():
    """示例2: 批量预测"""
    print("\n" + "="*80)
    print("示例2: 批量预测")
    print("="*80)
    
    # 创建预测器
    predictor = IDSPredictor()
    
    # 加载测试数据（前10条）
    test_file = Path('UNSW_NB15_testing-set.csv')
    if not test_file.exists():
        print("警告: 未找到测试数据文件")
        return
    
    df = pd.read_csv(test_file, nrows=10)
    
    print(f"\n加载了 {len(df)} 条样本")
    
    # 批量预测
    results = predictor.predict(df)
    
    # 统计结果
    print(f"\n预测结果统计:")
    normal_count = sum(1 for r in results if r['prediction'] == '正常')
    attack_count = sum(1 for r in results if r['prediction'] == '攻击')
    
    print(f"  正常: {normal_count} 条")
    print(f"  攻击: {attack_count} 条")
    
    # 显示详细结果
    print(f"\n详细结果:")
    for i, result in enumerate(results[:5]):  # 只显示前5条
        print(f"\n样本 {i+1}:")
        print(f"  预测: {result['prediction']}")
        if 'confidence' in result:
            print(f"  置信度: {result['confidence']:.4f}")
        if 'attack_type' in result:
            print(f"  攻击类型: {result['attack_type']}")


def example_custom_data():
    """示例3: 使用自定义数据"""
    print("\n" + "="*80)
    print("示例3: 使用自定义数据")
    print("="*80)
    
    # 创建预测器
    predictor = IDSPredictor()
    
    # 创建一个自定义样本（需要包含所有30个特征）
    # 注意：实际使用时，这些值应该来自真实的网络流量数据
    custom_sample = {
        'sttl': 254,
        'sbytes': 1000,
        'ct_state_ttl': 5,
        'sload': 500000,
        'smean': 500,
        'dttl': 128,
        'dbytes': 2000,
        'dmean': 1000,
        'dur': 0.5,
        'dload': 1000000,
        'dinpkt': 0.01,
        'dpkts': 10,
        'state': 'FIN',  # 分类特征，会被自动编码
        'sinpkt': 0.01,
        'ct_dst_sport_ltm': 2,
        'spkts': 5,
        'ct_src_dport_ltm': 2,
        'swin': 65535,
        'dwin': 65535,
        'ct_dst_src_ltm': 3,
        'djit': 0.001,
        'sjit': 0.001,
        'ct_dst_ltm': 2,
        'dloss': 0,
        'ct_srv_dst': 2,
        'ct_src_ltm': 2,
        'sloss': 0,
        'ct_srv_src': 2,
        'proto': 'tcp',  # 分类特征，会被自动编码
        'dtcpb': 0
    }
    
    print("\n使用自定义样本进行预测...")
    print("注意: 实际使用时，特征值应来自真实的网络流量数据")
    
    try:
        result = predictor.predict(custom_sample)
        
        print(f"\n预测结果:")
        print(f"  类型: {result['prediction']}")
        if 'confidence' in result:
            print(f"  置信度: {result['confidence']:.4f}")
    except Exception as e:
        print(f"\n错误: {e}")
        print("提示: 确保所有30个特征都已提供，且值在合理范围内")


def main():
    """主函数"""
    print("\n" + "="*80)
    print(" " * 15 + "磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 使用示例")
    print("="*80)
    
    # 检查模型是否存在
    if not Path('models').exists():
        print("\n错误: 未找到训练好的模型")
        print("请先运行以下命令训练模型:")
        print("  python main.py")
        return
    
    # 运行示例
    try:
        example_single_prediction()
        example_batch_prediction()
        example_custom_data()
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*80)
    print("示例运行完成!")
    print("="*80)
    print("\n更多信息请参考 README_PROJECT.md")


if __name__ == "__main__":
    main()

