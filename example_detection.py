#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测与分析功能使用示例
演示如何使用检测分析器进行网络流量检测和威胁分析
"""

from detection_analyzer import DetectionAnalyzer
import pandas as pd

def example_single_detection():
    """示例1: 单样本检测"""
    print("\n" + "="*80)
    print("示例1: 单样本检测与分析")
    print("="*80)
    
    # 创建检测分析器
    analyzer = DetectionAnalyzer()
    
    # 准备样本数据（包含30个特征）
    sample = {
        'sttl': 254,
        'sbytes': 496,
        'ct_state_ttl': 2,
        'sload': 180363632,
        'smean': 248,
        'dttl': 0,
        'dbytes': 0,
        'dmean': 0,
        'dur': 0.000011,
        'dload': 0,
        'dinpkt': 0,
        'dpkts': 0,
        'state': 'FIN',
        'sinpkt': 0.011,
        'ct_dst_sport_ltm': 1,
        'spkts': 2,
        'ct_src_dport_ltm': 1,
        'swin': 0,
        'dwin': 0,
        'ct_dst_src_ltm': 2,
        'djit': 0,
        'sjit': 0,
        'ct_dst_ltm': 1,
        'dloss': 0,
        'ct_srv_dst': 2,
        'ct_src_ltm': 1,
        'sloss': 0,
        'ct_srv_src': 2,
        'proto': 'tcp',
        'dtcpb': 0
    }
    
    # 检测和分析
    result = analyzer.detect_and_analyze(sample)
    
    # 显示结果
    print(f"\n检测结果:")
    print(f"  类型: {result['prediction']['type']}")
    print(f"  置信度: {result['prediction']['confidence']:.4f}")
    
    if result['prediction'].get('attack_type'):
        print(f"  攻击类型: {result['prediction']['attack_type']}")
    
    print(f"\n威胁分析:")
    print(f"  威胁得分: {result['threat_analysis']['threat_score']}/100")
    print(f"  威胁等级: {result['threat_analysis']['threat_level']}")
    
    if result['threat_analysis'].get('anomalous_features'):
        print(f"  异常特征数: {len(result['threat_analysis']['anomalous_features'])}")
        for feat in result['threat_analysis']['anomalous_features'][:3]:
            print(f"    - {feat['feature']}: {feat['value']} (风险: {feat['risk_score']:.2f})")
    
    if result.get('recommendations'):
        print(f"\n处理建议:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    
    # 生成报告
    analyzer.generate_report(result, 'reports/example_single_report.txt')
    print(f"\n详细报告已保存到: reports/example_single_report.txt")


def example_batch_detection():
    """示例2: 批量检测"""
    print("\n" + "="*80)
    print("示例2: 批量检测与分析")
    print("="*80)
    
    analyzer = DetectionAnalyzer()
    
    # 从CSV文件加载数据（如果存在）
    test_file = 'UNSW_NB15_testing-set.csv'
    if not Path(test_file).exists():
        print(f"\n未找到测试文件 {test_file}，跳过批量检测示例")
        return
    
    print(f"\n从 {test_file} 加载数据...")
    df = pd.read_csv(test_file, nrows=20)  # 只加载前20条
    
    # 批量检测
    batch_result = analyzer.detect_and_analyze(df)
    
    # 显示摘要
    if 'summary' in batch_result:
        summary = batch_result['summary']
        print(f"\n批量检测摘要:")
        print(f"  总样本数: {summary['total_samples']}")
        print(f"  正常流量: {summary['normal_count']}")
        print(f"  攻击流量: {summary['attack_count']}")
        print(f"  攻击率: {summary['attack_rate']}%")
        print(f"  平均威胁得分: {summary['avg_threat_score']}")
        print(f"  最高威胁得分: {summary['max_threat_score']}")
        
        if summary.get('attack_type_distribution'):
            print(f"\n攻击类型分布:")
            for atype, count in summary['attack_type_distribution'].items():
                print(f"  {atype}: {count}")


def example_history_analysis():
    """示例3: 历史分析"""
    print("\n" + "="*80)
    print("示例3: 检测历史分析")
    print("="*80)
    
    analyzer = DetectionAnalyzer()
    
    # 尝试加载历史记录
    analyzer.load_history()
    
    # 分析历史
    history = analyzer.analyze_history()
    
    if 'message' in history:
        print(f"\n{history['message']}")
        print("\n提示: 先运行一些检测以生成历史记录")
    else:
        print(f"\n历史分析结果 ({history['period']}):")
        print(f"  总检测数: {history['total_detections']}")
        print(f"  正常流量: {history['normal_count']}")
        print(f"  攻击流量: {history['attack_count']}")
        print(f"  攻击率: {history['attack_rate']}%")
        
        if history.get('attack_type_distribution'):
            print(f"\n攻击类型分布:")
            for atype, count in history['attack_type_distribution'].items():
                print(f"  {atype}: {count}")
        
        if history.get('threat_score_stats'):
            stats = history['threat_score_stats']
            print(f"\n威胁得分统计:")
            print(f"  平均: {stats['mean']}")
            print(f"  最大: {stats['max']}")
            print(f"  最小: {stats['min']}")
            print(f"  标准差: {stats['std']}")


def main():
    """主函数"""
    print("="*80)
    print(" " * 20 + "检测与分析功能使用示例")
    print("="*80)
    
    # 运行示例
    try:
        example_single_detection()
    except Exception as e:
        print(f"\n示例1执行失败: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        example_batch_detection()
    except Exception as e:
        print(f"\n示例2执行失败: {e}")
    
    try:
        example_history_analysis()
    except Exception as e:
        print(f"\n示例3执行失败: {e}")
    
    print("\n" + "="*80)
    print("示例执行完成!")
    print("="*80)


if __name__ == "__main__":
    from pathlib import Path
    main()

