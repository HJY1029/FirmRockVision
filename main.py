#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 主程序
完整的项目执行流程
"""

import sys
import argparse
from pathlib import Path
import warnings

warnings.filterwarnings('ignore')


def print_banner():
    """打印项目横幅"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统  ║
    ║                                                              ║
    ║    Intelligent Network Intrusion Detection & Threat Analysis ║
    ║                                                              ║
    ║         基于机器学习的智能网络安全威胁检测与分析平台           ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_preprocessing():
    """运行数据预处理"""
    print("\n" + "="*80)
    print("步骤 1/4: 数据预处理")
    print("="*80)
    
    try:
        from data_preprocessing import main as preprocess_main
        preprocess_main()
        return True
    except Exception as e:
        print(f"\n错误: 数据预处理失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_training():
    """运行模型训练"""
    print("\n" + "="*80)
    print("步骤 2/4: 模型训练")
    print("="*80)
    
    # 检查预处理数据是否存在
    if not Path('processed_data').exists():
        print("\n错误: 未找到预处理数据，请先运行数据预处理")
        return False
    
    try:
        from train_models import main as train_main
        train_main()
        return True
    except Exception as e:
        print(f"\n错误: 模型训练失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_visualization():
    """运行结果可视化"""
    print("\n" + "="*80)
    print("步骤 3/4: 结果可视化")
    print("="*80)
    
    # 检查模型是否存在
    if not Path('models').exists():
        print("\n错误: 未找到训练好的模型，请先运行模型训练")
        return False
    
    try:
        # 优先使用综合可视化
        try:
            from comprehensive_visualization import main as comprehensive_viz_main
            comprehensive_viz_main()
        except ImportError:
            # 如果不存在，使用基础可视化
            from visualize_results import main as viz_main
            viz_main()
        return True
    except Exception as e:
        print(f"\n错误: 结果可视化失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_prediction():
    """运行预测示例"""
    print("\n" + "="*80)
    print("步骤 4/5: 基础预测示例")
    print("="*80)
    
    try:
        from predict import main as predict_main
        predict_main()
        return True
    except Exception as e:
        print(f"\n错误: 预测失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_detection_analysis():
    """运行检测与分析"""
    print("\n" + "="*80)
    print("步骤 5/5: 智能检测与分析")
    print("="*80)
    
    # 检查模型是否存在
    if not Path('models').exists():
        print("\n错误: 未找到训练好的模型，请先运行模型训练")
        return False
    
    try:
        from detection_analyzer import main as detection_main
        detection_main()
        return True
    except Exception as e:
        print(f"\n错误: 检测分析失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python main.py                    # 运行完整流程
  python main.py --step preprocess  # 只运行数据预处理
  python main.py --step train       # 只运行模型训练
  python main.py --step visualize   # 只运行可视化
  python main.py --step predict     # 只运行基础预测示例
  python main.py --step analyze     # 只运行智能检测与分析
        """
    )
    
    parser.add_argument(
        '--step',
        choices=['preprocess', 'train', 'visualize', 'predict', 'analyze', 'all'],
        default='all',
        help='要执行的步骤 (默认: all)'
    )
    
    parser.add_argument(
        '--skip-preprocess',
        action='store_true',
        help='跳过数据预处理（假设已存在预处理数据）'
    )
    
    parser.add_argument(
        '--skip-train',
        action='store_true',
        help='跳过模型训练（假设已存在训练好的模型）'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    success = True
    
    if args.step == 'all':
        # 运行完整流程
        if not args.skip_preprocess:
            success = run_preprocessing()
            if not success:
                print("\n数据预处理失败，终止执行")
                return
        
        if success and not args.skip_train:
            success = run_training()
            if not success:
                print("\n模型训练失败，终止执行")
                return
        
        if success:
            success = run_visualization()
        
        if success:
            run_prediction()
        
        if success:
            run_detection_analysis()
    
    elif args.step == 'preprocess':
        success = run_preprocessing()
    
    elif args.step == 'train':
        success = run_training()
    
    elif args.step == 'visualize':
        success = run_visualization()
    
    elif args.step == 'predict':
        run_prediction()
    
    elif args.step == 'analyze':
        run_detection_analysis()
    
    if success:
        print("\n" + "="*80)
        print("所有步骤执行完成!")
        print("="*80)
        print("\n生成的文件:")
        print("  - processed_data/     : 预处理后的数据")
        print("  - models/              : 训练好的模型")
        print("  - results/            : 评估结果和可视化图表")
        print("  - reports/            : 检测分析报告")
        print("  - detection_history.json : 检测历史记录")
        print("\n查看 results/ 目录中的图表了解模型性能")
        print("查看 reports/ 目录中的报告了解详细检测分析结果")


if __name__ == "__main__":
    main()

