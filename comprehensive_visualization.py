#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 综合可视化分析
包含二分类检测、多分类识别、模型对比的完整可视化
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import pickle
import warnings
from sklearn.metrics import (
    confusion_matrix, classification_report, roc_curve, 
    roc_auc_score, precision_recall_curve, auc
)

warnings.filterwarnings('ignore')

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS', 'Microsoft YaHei']
plt.rcParams['axes.unicode_minus'] = False

# 设置图表样式
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 8)


def load_data_and_models():
    """加载数据和模型"""
    data_dir = Path('processed_data')
    models_dir = Path('models')
    
    if not data_dir.exists():
        print("错误: 未找到预处理数据，请先运行 data_preprocessing.py")
        return None, None, None
    
    # 加载数据
    print("加载数据...")
    X_test = pd.read_csv(data_dir / 'X_test.csv')
    y_test = pd.read_csv(data_dir / 'y_test.csv').values.ravel()
    
    # 加载攻击类型（如果存在）
    attack_cats_test = None
    if (data_dir / 'attack_cat_test.csv').exists():
        attack_cats_test = pd.read_csv(data_dir / 'attack_cat_test.csv').values.ravel()
    
    # 加载模型
    models = {}
    if models_dir.exists():
        print("加载模型...")
        for model_file in models_dir.glob('*.pkl'):
            if 'encoder' not in model_file.stem:
                model_name = model_file.stem
                try:
                    with open(model_file, 'rb') as f:
                        models[model_name] = pickle.load(f)
                    print(f"  已加载: {model_name}")
                except Exception as e:
                    print(f"  警告: 无法加载 {model_name}: {e}")
    
    return X_test, y_test, attack_cats_test, models


def visualize_binary_classification(X_test, y_test, models):
    """可视化二分类检测结果"""
    print("\n" + "="*80)
    print("生成二分类检测可视化")
    print("="*80)
    
    binary_models = {k: v for k, v in models.items() if 'binary' in k}
    
    if len(binary_models) == 0:
        print("警告: 没有找到二分类模型")
        return
    
    n_models = len(binary_models)
    fig = plt.figure(figsize=(20, 12))
    gs = fig.add_gridspec(3, n_models, hspace=0.3, wspace=0.3)
    
    fig.suptitle('二分类检测结果 - 正常 vs 攻击', fontsize=18, fontweight='bold', y=0.98)
    
    model_names = []
    accuracies = []
    precisions = []
    recalls = []
    f1_scores = []
    roc_aucs = []
    
    for idx, (model_name, model) in enumerate(binary_models.items()):
        display_name = model_name.replace('_binary', '')
        model_names.append(display_name)
        
        # 预测
        y_pred = model.predict(X_test)
        y_pred_proba = None
        if hasattr(model, 'predict_proba'):
            y_pred_proba = model.predict_proba(X_test)[:, 1]
        
        # 计算指标
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        accuracies.append(acc)
        precisions.append(prec)
        recalls.append(rec)
        f1_scores.append(f1)
        
        # ROC AUC
        roc_auc = None
        if y_pred_proba is not None:
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
                roc_aucs.append(roc_auc)
            except:
                roc_aucs.append(None)
        else:
            roc_aucs.append(None)
        
        # 1. 混淆矩阵
        ax1 = fig.add_subplot(gs[0, idx])
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax1,
                   xticklabels=['正常', '攻击'],
                   yticklabels=['正常', '攻击'],
                   cbar_kws={'label': '样本数'})
        ax1.set_title(f'{display_name}\n准确率: {acc:.4f}', fontsize=12, fontweight='bold')
        ax1.set_ylabel('实际标签', fontsize=10)
        ax1.set_xlabel('预测标签', fontsize=10)
        
        # 2. ROC曲线
        ax2 = fig.add_subplot(gs[1, idx])
        if y_pred_proba is not None:
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            ax2.plot(fpr, tpr, linewidth=2, label=f'AUC = {roc_auc:.4f}')
            ax2.plot([0, 1], [0, 1], 'k--', linewidth=1, label='随机猜测')
            ax2.set_xlim([0.0, 1.0])
            ax2.set_ylim([0.0, 1.05])
            ax2.set_xlabel('假阳性率 (FPR)', fontsize=10)
            ax2.set_ylabel('真阳性率 (TPR)', fontsize=10)
            ax2.set_title('ROC曲线', fontsize=11, fontweight='bold')
            ax2.legend(loc="lower right", fontsize=9)
            ax2.grid(alpha=0.3)
        else:
            ax2.text(0.5, 0.5, '无概率预测', ha='center', va='center', fontsize=12)
            ax2.set_title('ROC曲线', fontsize=11, fontweight='bold')
        
        # 3. 精确率-召回率曲线
        ax3 = fig.add_subplot(gs[2, idx])
        if y_pred_proba is not None:
            precision, recall, _ = precision_recall_curve(y_test, y_pred_proba)
            pr_auc = auc(recall, precision)
            ax3.plot(recall, precision, linewidth=2, label=f'PR-AUC = {pr_auc:.4f}')
            ax3.set_xlim([0.0, 1.0])
            ax3.set_ylim([0.0, 1.05])
            ax3.set_xlabel('召回率 (Recall)', fontsize=10)
            ax3.set_ylabel('精确率 (Precision)', fontsize=10)
            ax3.set_title('精确率-召回率曲线', fontsize=11, fontweight='bold')
            ax3.legend(loc="lower left", fontsize=9)
            ax3.grid(alpha=0.3)
        else:
            ax3.text(0.5, 0.5, '无概率预测', ha='center', va='center', fontsize=12)
            ax3.set_title('精确率-召回率曲线', fontsize=11, fontweight='bold')
    
    # 保存图表
    output_path = Path('results') / '01_二分类检测结果.png'
    Path('results').mkdir(exist_ok=True)
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  已保存: {output_path}")
    plt.close()
    
    # 生成模型对比柱状图
    fig, axes = plt.subplots(2, 2, figsize=(16, 10))
    fig.suptitle('二分类模型性能对比', fontsize=16, fontweight='bold')
    
    metrics_data = {
        '准确率': accuracies,
        '精确率': precisions,
        '召回率': recalls,
        'F1分数': f1_scores
    }
    
    for idx, (metric_name, values) in enumerate(metrics_data.items()):
        ax = axes[idx // 2, idx % 2]
        bars = ax.bar(range(len(model_names)), values, 
                     color=sns.color_palette("husl", len(model_names)))
        ax.set_xticks(range(len(model_names)))
        ax.set_xticklabels(model_names, rotation=45, ha='right')
        ax.set_ylabel(metric_name, fontsize=12)
        ax.set_title(f'{metric_name} 对比', fontsize=13, fontweight='bold')
        ax.set_ylim([0, 1.1])
        ax.grid(axis='y', alpha=0.3)
        
        # 添加数值标签
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                   f'{val:.4f}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    output_path = Path('results') / '02_二分类模型性能对比.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  已保存: {output_path}")
    plt.close()
    
    return {
        'model_names': model_names,
        'accuracies': accuracies,
        'precisions': precisions,
        'recalls': recalls,
        'f1_scores': f1_scores,
        'roc_aucs': roc_aucs
    }


def visualize_multiclass_classification(X_test, y_test, attack_cats_test, models):
    """可视化多分类识别结果（攻击类型分类）"""
    print("\n" + "="*80)
    print("生成多分类识别可视化")
    print("="*80)
    
    if attack_cats_test is None:
        print("警告: 未找到攻击类型数据，跳过多分类可视化")
        return None
    
    # 只使用攻击样本
    attack_mask = y_test == 1
    if attack_mask.sum() == 0:
        print("警告: 测试集中没有攻击样本")
        return None
    
    X_test_attack = X_test[attack_mask]
    attack_cats_test_filtered = attack_cats_test[attack_mask]
    
    # 找到多分类模型
    multi_models = {}
    encoders = {}
    
    for model_name, model in models.items():
        if 'Multi' in model_name or 'multi' in model_name:
            if 'encoder' not in model_name:
                multi_models[model_name] = model
                # 查找对应的编码器
                encoder_name = f'{model_name}_encoder'
                if encoder_name in models:
                    encoders[model_name] = models[encoder_name]
    
    if len(multi_models) == 0:
        print("警告: 没有找到多分类模型")
        return None
    
    # 编码攻击类型
    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    y_test_encoded = le.fit_transform(attack_cats_test_filtered)
    attack_types = le.classes_
    
    print(f"\n攻击类型 ({len(attack_types)} 种):")
    for i, atype in enumerate(attack_types):
        count = (attack_cats_test_filtered == atype).sum()
        print(f"  {i+1}. {atype:<20} 样本数: {count:>6,}")
    
    # 为每个模型生成可视化
    for model_name, model in multi_models.items():
        display_name = model_name.replace('_Multi', '').replace('_multi', '')
        
        # 预测
        y_pred_encoded = model.predict(X_test_attack)
        y_pred = le.inverse_transform(y_pred_encoded)
        
        # 计算指标
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        acc = accuracy_score(y_test_encoded, y_pred_encoded)
        prec = precision_score(y_test_encoded, y_pred_encoded, average='weighted', zero_division=0)
        rec = recall_score(y_test_encoded, y_pred_encoded, average='weighted', zero_division=0)
        f1 = f1_score(y_test_encoded, y_pred_encoded, average='weighted', zero_division=0)
        
        # 创建可视化
        fig, axes = plt.subplots(2, 2, figsize=(18, 14))
        fig.suptitle(f'多分类识别结果 - {display_name}\n攻击类型分类', 
                     fontsize=16, fontweight='bold')
        
        # 1. 混淆矩阵
        ax1 = axes[0, 0]
        cm = confusion_matrix(y_test_encoded, y_pred_encoded)
        sns.heatmap(cm, annot=True, fmt='d', cmap='YlOrRd', ax=ax1,
                   xticklabels=attack_types, yticklabels=attack_types,
                   cbar_kws={'label': '样本数'})
        ax1.set_title(f'混淆矩阵\n准确率: {acc:.4f}', fontsize=12, fontweight='bold')
        ax1.set_ylabel('实际攻击类型', fontsize=11)
        ax1.set_xlabel('预测攻击类型', fontsize=11)
        plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')
        plt.setp(ax1.get_yticklabels(), rotation=0)
        
        # 2. 每个攻击类型的性能指标
        ax2 = axes[0, 1]
        from sklearn.metrics import precision_recall_fscore_support
        precisions_per_class, recalls_per_class, f1s_per_class, _ = \
            precision_recall_fscore_support(y_test_encoded, y_pred_encoded, 
                                          zero_division=0, labels=range(len(attack_types)))
        
        x = np.arange(len(attack_types))
        width = 0.25
        
        ax2.bar(x - width, precisions_per_class, width, label='精确率', alpha=0.8)
        ax2.bar(x, recalls_per_class, width, label='召回率', alpha=0.8)
        ax2.bar(x + width, f1s_per_class, width, label='F1分数', alpha=0.8)
        
        ax2.set_xlabel('攻击类型', fontsize=11)
        ax2.set_ylabel('分数', fontsize=11)
        ax2.set_title('各类攻击类型性能指标', fontsize=12, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(attack_types, rotation=45, ha='right')
        ax2.set_ylim([0, 1.1])
        ax2.legend(fontsize=10)
        ax2.grid(axis='y', alpha=0.3)
        
        # 3. 攻击类型分布（实际 vs 预测）
        ax3 = axes[1, 0]
        actual_counts = pd.Series(attack_cats_test_filtered).value_counts().sort_index()
        pred_counts = pd.Series(y_pred).value_counts().sort_index()
        
        x = np.arange(len(attack_types))
        width = 0.35
        
        ax3.bar(x - width/2, [actual_counts.get(at, 0) for at in attack_types], 
               width, label='实际', alpha=0.8)
        ax3.bar(x + width/2, [pred_counts.get(at, 0) for at in attack_types], 
               width, label='预测', alpha=0.8)
        
        ax3.set_xlabel('攻击类型', fontsize=11)
        ax3.set_ylabel('样本数', fontsize=11)
        ax3.set_title('攻击类型分布对比', fontsize=12, fontweight='bold')
        ax3.set_xticks(x)
        ax3.set_xticklabels(attack_types, rotation=45, ha='right')
        ax3.legend(fontsize=10)
        ax3.grid(axis='y', alpha=0.3)
        
        # 4. 分类报告热力图
        ax4 = axes[1, 1]
        report = classification_report(y_test_encoded, y_pred_encoded,
                                      target_names=attack_types,
                                      output_dict=True, zero_division=0)
        
        # 提取每个类别的指标
        metrics_data = []
        for atype in attack_types:
            if atype in report:
                metrics_data.append([
                    report[atype]['precision'],
                    report[atype]['recall'],
                    report[atype]['f1-score'],
                    report[atype]['support']
                ])
            else:
                metrics_data.append([0, 0, 0, 0])
        
        metrics_df = pd.DataFrame(metrics_data, 
                                 index=attack_types,
                                 columns=['精确率', '召回率', 'F1分数', '样本数'])
        
        # 归一化样本数用于显示
        metrics_df_display = metrics_df.copy()
        metrics_df_display['样本数'] = metrics_df_display['样本数'] / metrics_df_display['样本数'].max()
        
        sns.heatmap(metrics_df_display, annot=True, fmt='.3f', cmap='RdYlGn', 
                   ax=ax4, cbar_kws={'label': '归一化分数'})
        ax4.set_title('分类报告热力图', fontsize=12, fontweight='bold')
        ax4.set_ylabel('攻击类型', fontsize=11)
        plt.setp(ax4.get_xticklabels(), rotation=0)
        plt.setp(ax4.get_yticklabels(), rotation=0)
        
        plt.tight_layout()
        output_path = Path('results') / f'03_多分类识别结果_{display_name}.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"  已保存: {output_path}")
        plt.close()
    
    return {
        'attack_types': attack_types,
        'model_performance': {}
    }


def visualize_model_comparison(binary_results, multi_results):
    """可视化模型对比"""
    print("\n" + "="*80)
    print("生成模型对比可视化")
    print("="*80)
    
    if binary_results is None:
        print("警告: 没有二分类结果")
        return
    
    # 创建综合对比图
    fig, axes = plt.subplots(2, 2, figsize=(18, 12))
    fig.suptitle('模型综合性能对比', fontsize=18, fontweight='bold')
    
    model_names = binary_results['model_names']
    
    # 1. 所有指标对比（雷达图风格）
    ax1 = axes[0, 0]
    metrics = ['准确率', '精确率', '召回率', 'F1分数']
    values = [
        binary_results['accuracies'],
        binary_results['precisions'],
        binary_results['recalls'],
        binary_results['f1_scores']
    ]
    
    x = np.arange(len(metrics))
    width = 0.2
    
    for i, (name, vals) in enumerate(zip(model_names, zip(*values))):
        offset = (i - len(model_names)/2 + 0.5) * width
        ax1.bar(x + offset, vals, width, label=name, alpha=0.8)
    
    ax1.set_xlabel('评估指标', fontsize=12)
    ax1.set_ylabel('分数', fontsize=12)
    ax1.set_title('所有模型性能指标对比', fontsize=13, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(metrics)
    ax1.set_ylim([0, 1.1])
    ax1.legend(fontsize=10)
    ax1.grid(axis='y', alpha=0.3)
    
    # 2. ROC AUC对比（如果有）
    ax2 = axes[0, 1]
    roc_aucs = [r for r in binary_results['roc_aucs'] if r is not None]
    roc_names = [n for n, r in zip(model_names, binary_results['roc_aucs']) if r is not None]
    
    if len(roc_aucs) > 0:
        bars = ax2.bar(range(len(roc_names)), roc_aucs, 
                      color=sns.color_palette("husl", len(roc_names)))
        ax2.set_xticks(range(len(roc_names)))
        ax2.set_xticklabels(roc_names, rotation=45, ha='right')
        ax2.set_ylabel('ROC AUC', fontsize=12)
        ax2.set_title('ROC AUC 对比', fontsize=13, fontweight='bold')
        ax2.set_ylim([0, 1.1])
        ax2.grid(axis='y', alpha=0.3)
        
        for bar, val in zip(bars, roc_aucs):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{val:.4f}', ha='center', va='bottom', fontsize=10)
    else:
        ax2.text(0.5, 0.5, '无ROC AUC数据', ha='center', va='center', fontsize=12)
        ax2.set_title('ROC AUC 对比', fontsize=13, fontweight='bold')
    
    # 3. 综合评分（平均所有指标）
    ax3 = axes[1, 0]
    overall_scores = []
    for i in range(len(model_names)):
        score = (binary_results['accuracies'][i] + 
                binary_results['precisions'][i] + 
                binary_results['recalls'][i] + 
                binary_results['f1_scores'][i]) / 4
        overall_scores.append(score)
    
    bars = ax3.bar(range(len(model_names)), overall_scores,
                  color=sns.color_palette("husl", len(model_names)))
    ax3.set_xticks(range(len(model_names)))
    ax3.set_xticklabels(model_names, rotation=45, ha='right')
    ax3.set_ylabel('综合评分', fontsize=12)
    ax3.set_title('模型综合评分（平均所有指标）', fontsize=13, fontweight='bold')
    ax3.set_ylim([0, 1.1])
    ax3.grid(axis='y', alpha=0.3)
    
    for bar, val in zip(bars, overall_scores):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{val:.4f}', ha='center', va='bottom', fontsize=10)
    
    # 4. 性能指标表格
    ax4 = axes[1, 1]
    ax4.axis('tight')
    ax4.axis('off')
    
    table_data = []
    for i, name in enumerate(model_names):
        row = [
            name,
            f"{binary_results['accuracies'][i]:.4f}",
            f"{binary_results['precisions'][i]:.4f}",
            f"{binary_results['recalls'][i]:.4f}",
            f"{binary_results['f1_scores'][i]:.4f}"
        ]
        if binary_results['roc_aucs'][i] is not None:
            row.append(f"{binary_results['roc_aucs'][i]:.4f}")
        else:
            row.append("N/A")
        table_data.append(row)
    
    columns = ['模型', '准确率', '精确率', '召回率', 'F1分数', 'ROC AUC']
    table = ax4.table(cellText=table_data, colLabels=columns,
                     cellLoc='center', loc='center',
                     colWidths=[0.2, 0.15, 0.15, 0.15, 0.15, 0.15])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    # 设置表头样式
    for i in range(len(columns)):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    ax4.set_title('模型性能指标汇总表', fontsize=13, fontweight='bold', pad=20)
    
    plt.tight_layout()
    output_path = Path('results') / '04_模型综合对比.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  已保存: {output_path}")
    plt.close()


def create_data_explanation():
    """创建数据文件说明图"""
    print("\n" + "="*80)
    print("生成数据文件说明")
    print("="*80)
    
    fig, ax = plt.subplots(figsize=(16, 10))
    ax.axis('off')
    
    explanation_text = """
    数据文件说明
    
    📁 processed_data/ 目录下的文件：
    
    1. X_train.csv / X_test.csv
       - 含义：特征数据（Features）
       - 内容：30个经过选择和预处理的特征列
       - 用途：输入到机器学习模型进行训练/预测
       - 示例：sttl, sbytes, ct_state_ttl, sload, smean 等
    
    2. y_train.csv / y_test.csv
       - 含义：标签数据（Labels）
       - 内容：二分类标签（0=正常流量，1=攻击流量）
       - 用途：用于训练和评估模型
       - 示例：0, 0, 1, 0, 1, ...
    
    3. attack_cat_train.csv / attack_cat_test.csv
       - 含义：攻击类型标签（Attack Categories）
       - 内容：9种攻击类型的名称
       - 用途：用于多分类任务（识别具体攻击类型）
       - 示例：Normal, Fuzzers, Analysis, Backdoors, DoS, Exploits, ...
    
    4. preprocessor.pkl
       - 含义：数据预处理器
       - 内容：保存的特征编码器和标准化器
       - 用途：对新数据进行相同的预处理
    
    📊 数据流程：
    
    原始数据 → 特征选择 → 数据预处理 → 模型训练 → 模型评估
    
    UNSW_NB15_training-set.csv  →  X_train.csv + y_train.csv
    UNSW_NB15_testing-set.csv   →  X_test.csv + y_test.csv
    
    """
    
    ax.text(0.5, 0.5, explanation_text, 
           transform=ax.transAxes,
           fontsize=14,
           verticalalignment='center',
           horizontalalignment='center',
           bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5),
           family='monospace')
    
    ax.set_title('数据文件说明', fontsize=18, fontweight='bold', pad=20)
    
    output_path = Path('results') / '00_数据文件说明.png'
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  已保存: {output_path}")
    plt.close()


def main():
    """主函数"""
    print("\n" + "="*80)
    print(" " * 10 + "磐石之眼（FirmRock Vision）- 综合可视化分析")
    print("="*80)
    
    # 创建结果目录
    Path('results').mkdir(exist_ok=True)
    
    # 创建数据文件说明
    create_data_explanation()
    
    # 加载数据和模型
    result = load_data_and_models()
    if result is None:
        return
    
    X_test, y_test, attack_cats_test, models = result
    
    if len(models) == 0:
        print("错误: 没有找到训练好的模型，请先运行 train_models.py")
        return
    
    # 1. 二分类检测可视化
    binary_results = visualize_binary_classification(X_test, y_test, models)
    
    # 2. 多分类识别可视化
    multi_results = visualize_multiclass_classification(X_test, y_test, attack_cats_test, models)
    
    # 3. 模型对比可视化
    visualize_model_comparison(binary_results, multi_results)
    
    print("\n" + "="*80)
    print("综合可视化分析完成!")
    print("="*80)
    print(f"\n所有图表已保存到: {Path('results').absolute()}")
    print("\n生成的图表文件：")
    print("  00_数据文件说明.png - 数据文件说明")
    print("  01_二分类检测结果.png - 二分类检测详细结果")
    print("  02_二分类模型性能对比.png - 二分类模型性能对比")
    print("  03_多分类识别结果_*.png - 多分类识别详细结果（每个模型一张）")
    print("  04_模型综合对比.png - 模型综合性能对比")


if __name__ == "__main__":
    main()

