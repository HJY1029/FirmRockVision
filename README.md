# 磐石之眼（FirmRock Vision）

## 基于集成学习与深度特征分析的智能网络入侵检测与威胁分析平台

### 🛡️ 面向企业级网络安全防护 | 支持实时威胁检测、多维度威胁评分与智能安全决策

---

**磐石之眼（FirmRock Vision）** 是一款基于**集成学习（Ensemble Learning）**和**深度特征分析**的企业级智能网络入侵检测与威胁分析平台。系统采用**Random Forest、XGBoost、LightGBM**多模型集成架构，结合**30维关键特征工程**和**多维度威胁评分机制**，为网络安全团队提供高精度、实时的网络流量异常检测、攻击类型识别和深度威胁分析能力。

**核心定位**：面向企业安全运维团队、网络安全研究人员和系统管理员，提供生产级可用的智能安全检测解决方案。

## 🎯 技术亮点

- **🧠 集成学习架构**：Random Forest + XGBoost + LightGBM 多模型集成，准确率高达92%
- **🔬 深度特征工程**：基于统计方法的30维关键特征提取与优化
- **📊 多维度威胁评分**：0-100分综合威胁评分系统，支持5级威胁等级划分
- **⚡ 实时检测能力**：单样本检测<1秒，批量检测（100条）<10秒
- **🌐 企业级Web平台**：基于Flask的现代化Web界面，支持单样本/批量检测、历史分析
- **📈 可视化分析**：完整的性能评估图表、攻击类型分布、趋势分析

## 🎯 适用场景

- **企业安全运维**：实时监控网络流量，快速识别安全威胁
- **安全研究分析**：基于UNSW-NB15数据集的网络安全研究
- **系统安全防护**：为关键系统提供智能入侵检测能力
- **安全事件响应**：快速定位攻击类型，提供针对性处理建议

## 📋 核心功能

### 1. 智能检测功能

- **二分类检测**：快速识别网络流量是正常还是攻击
- **多分类识别**：对攻击流量进行细分类（9种攻击类型）
- **威胁评分**：基于多维度特征计算综合威胁得分（0-100分）
- **置信度评估**：提供模型预测的置信度，辅助决策

### 2. 深度分析功能

- **威胁特征分析**：识别异常网络特征，定位攻击行为
- **风险指标识别**：自动检测高风险网络行为模式
- **攻击类型识别**：精确识别9种攻击类型（Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms）
- **特征重要性分析**：基于30个关键特征进行深度分析

### 3. 报告与统计功能

- **详细检测报告**：自动生成包含威胁分析、处理建议的完整报告
- **批量检测分析**：支持批量数据检测和统计分析
- **历史记录管理**：保存检测历史，支持历史数据分析
- **趋势分析**：分析攻击类型分布和威胁等级趋势

### 4. 模型与性能

- **集成学习架构**：Random Forest, XGBoost, LightGBM 多模型集成
- **高性能表现**：准确率92%，精确率92%，召回率92%，F1分数92%
- **模型对比分析**：多算法性能对比与可视化评估
- **生产级性能**：支持大规模数据批量处理

## 项目结构

```
UNSW_NB15/
├── data_preprocessing.py          # 数据预处理模块
├── train_models.py                # 模型训练模块
├── visualize_results.py           # 结果可视化模块
├── predict.py                     # 预测接口模块
├── detection_analyzer.py           # 检测与分析模块（新增）
├── main.py                        # 主程序入口
├── feature_selection_statistical.py  # 特征选择脚本（已有）
├── requirements.txt               # 项目依赖
├── README.md                      # 特征选择说明
├── README_PROJECT.md              # 项目说明（本文件）
│
├── processed_data/                # 预处理后的数据（运行后生成）
│   ├── X_train.csv
│   ├── y_train.csv
│   ├── X_test.csv
│   ├── y_test.csv
│   ├── attack_cat_train.csv
│   ├── attack_cat_test.csv
│   └── preprocessor.pkl
│
├── models/                        # 训练好的模型（运行后生成）
│   ├── RandomForest_binary.pkl
│   ├── XGBoost_binary.pkl
│   ├── LightGBM_binary.pkl
│   └── ...
│
├── results/                       # 评估结果和图表（运行后生成）
│   ├── model_comparison.csv
│   ├── 01_model_comparison.png
│   ├── 02_confusion_matrices.png
│   ├── 03_roc_curves.png
│   ├── 04_training_time.png
│   └── 05_attack_type_distribution.png
│
├── reports/                       # 检测分析报告（运行后生成）
│   └── detection_report_*.txt
│
└── detection_history.json         # 检测历史记录（运行后生成）
│
└── feature_selection_results/     # 特征选择结果（已有）
    ├── 04_selected_features.txt
    └── ...
```

## 环境要求

- Python 3.8+
- 推荐内存: 8GB+
- 磁盘空间: 至少2GB（用于数据集和模型）

## 安装依赖

```bash
pip install -r requirements.txt
```

```shell
pip install xgboost -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
```



### 依赖说明

- **必需依赖**：
  - `pandas`: 数据处理
  - `numpy`: 数值计算
  - `scikit-learn`: 机器学习算法和工具
  - `matplotlib`: 基础绘图
  - `seaborn`: 高级可视化

- **可选依赖**（提升性能）：
  - `xgboost`: XGBoost算法（推荐）
  - `lightgbm`: LightGBM算法（推荐）

## 快速开始

### 方式1：启动Web平台（推荐，面向企业用户）

```bash
# 1. 确保已安装依赖
pip install -r requirements.txt

# 2. 确保模型已训练（如果还没有）
python main.py --step train

# 3. 启动Web服务器
python app.py
```

然后在浏览器中访问：`http://127.0.0.1:5000`

Web平台提供：

- 友好的图形界面（蓝绿色动态渐变设计）
- 单样本和批量检测功能
- 实时威胁分析和报告生成
- 检测历史查看和统计分析

详细使用说明请查看：[WEB平台使用说明.md](WEB平台使用说明.md)

### 方式2：运行完整流程（命令行）

```bash
python main.py
```

这将自动执行：

1. 数据预处理
2. 模型训练
3. 结果可视化
4. 预测示例
5. 智能检测与分析

### 方式2：分步执行

#### 步骤1：数据预处理

```bash
python data_preprocessing.py
```

或使用主程序：

```bash
python main.py --step preprocess
```

**输出**：

- `processed_data/` 目录下的预处理数据
- `preprocessor.pkl` 预处理器文件

#### 步骤2：模型训练

```bash
python train_models.py
```

或使用主程序：

```bash
python main.py --step train
```

**输出**：

- `models/` 目录下的训练好的模型
- `results/model_comparison.csv` 模型性能对比表

#### 步骤3：结果可视化

```bash
python visualize_results.py
```

或使用主程序：

```bash
python main.py --step visualize
```

**输出**：

- `results/` 目录下的各种性能图表

#### 步骤4：检测与分析示例

```bash
python detection_analyzer.py
```

或使用基础预测接口：

```bash
python predict.py
```

或使用主程序：

```bash
python main.py --step predict
```

### 方式3：跳过已有步骤

如果已经完成某些步骤，可以跳过：

```bash
# 跳过预处理，直接训练
python main.py --skip-preprocess

# 跳过训练，直接可视化
python main.py --skip-train
```

## 使用检测与分析功能

### 方式1：使用检测分析器（推荐）

检测分析器提供了完整的检测、分析和报告生成功能：

```python
from detection_analyzer import DetectionAnalyzer

# 创建检测分析器
analyzer = DetectionAnalyzer()

# 单样本检测和分析
sample = {
    'sttl': 254,
    'sbytes': 496,
    'ct_state_ttl': 2,
    # ... 其他30个特征
}

result = analyzer.detect_and_analyze(sample)

# 查看结果
print(f"检测类型: {result['prediction']['type']}")
print(f"威胁得分: {result['threat_analysis']['threat_score']}/100")
print(f"威胁等级: {result['threat_analysis']['threat_level']}")

# 生成详细报告
analyzer.generate_report(result, 'reports/detection_report.txt')

# 批量检测
import pandas as pd
df = pd.read_csv('your_data.csv')
batch_result = analyzer.detect_and_analyze(df)
print(batch_result['summary'])

# 查看历史分析
history = analyzer.analyze_history(days=7)
print(history)
```

### 方式2：使用基础预测接口

```python
from predict import IDSPredictor

# 创建预测器
predictor = IDSPredictor()

# 准备数据（字典格式，包含30个特征）
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
    'state': 0,  # 需要编码后的值
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
    'proto': 0,  # 需要编码后的值
    'dtcpb': 0
}

# 预测
result = predictor.predict(sample)

# 查看结果
print(f"预测结果: {result['prediction']}")
print(f"置信度: {result['confidence']:.4f}")

if 'attack_type' in result:
    print(f"攻击类型: {result['attack_type']}")
```

### 批量预测

```python
import pandas as pd
from predict import IDSPredictor

predictor = IDSPredictor()

# 从CSV文件加载数据
df = pd.read_csv('your_data.csv')

# 批量预测
results = predictor.predict(df)

# 查看结果
for i, result in enumerate(results):
    print(f"样本 {i+1}: {result['prediction']}")
```

## 模型说明

### 支持的算法

1. **Random Forest（随机森林）**
   - 默认使用，无需额外依赖
   - 稳定可靠，适合作为基准模型

2. **XGBoost**（可选）
   - 需要安装：`pip install xgboost`
   - 通常性能最佳，训练速度较快

3. **LightGBM**（可选）
   - 需要安装：`pip install lightgbm`
   - 训练速度最快，内存占用小

### 模型任务

1. **二分类任务**（正常 vs 攻击）
   - 模型文件：`*_binary.pkl`
   - 输出：正常/攻击 + 置信度

2. **多分类任务**（攻击类型识别）
   - 模型文件：`*_Multi.pkl`
   - 输出：9种攻击类型之一
   - 攻击类型：Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms

## 🔬 核心技术：特征工程

项目采用**统计特征选择方法**，从原始49维特征中提取30个关键特征，显著提升模型性能：

**Top 10 特征**（按重要性排序）：

1. `sttl` - 源端TTL值
2. `sbytes` - 源端字节数
3. `ct_state_ttl` - 状态-TTL统计
4. `sload` - 源端负载
5. `smean` - 源端平均包大小
6. `dttl` - 目标端TTL值
7. `dbytes` - 目标端字节数
8. `dmean` - 目标端平均包大小
9. `dur` - 连接持续时间
10. `dload` - 目标端负载

完整特征列表见：`feature_selection_results/04_selected_features.txt`

## 评估指标

模型评估使用以下指标：

- **准确率 (Accuracy)**: 正确预测的比例
- **精确率 (Precision)**: 预测为攻击中真正是攻击的比例
- **召回率 (Recall)**: 所有攻击中被正确识别的比例
- **F1分数**: 精确率和召回率的调和平均
- **ROC AUC**: ROC曲线下面积（仅二分类）

## 结果文件说明

### 模型对比表 (`results/model_comparison.csv`)

包含所有模型的性能指标对比。

### 可视化图表

1. **01_model_comparison.png**: 模型性能对比（准确率、精确率、召回率、F1）
2. **02_confusion_matrices.png**: 混淆矩阵对比
3. **03_roc_curves.png**: ROC曲线对比
4. **04_training_time.png**: 训练和预测时间对比
5. **05_attack_type_distribution.png**: 攻击类型分布

## 数据集信息

**UNSW-NB15数据集**：

- 总记录数: 2,540,047 条
- 训练集: 175,341 条
- 测试集: 82,332 条
- 原始特征: 49 个
- 使用特征: 30 个（经过特征选择）
- 标签: Normal (0) / Attack (1)
- 攻击类型: 9 种

## 📊 性能指标

基于UNSW-NB15数据集测试，系统性能表现：

| 模型算法          | 准确率 | 精确率 | 召回率 | F1分数 | 训练速度 |
| ----------------- | ------ | ------ | ------ | ------ | -------- |
| **Random Forest** | ~90%   | ~90%   | ~90%   | ~90%   | 中等     |
| **XGBoost**       | ~92%   | ~92%   | ~92%   | ~92%   | 快       |
| **LightGBM**      | ~91%   | ~91%   | ~91%   | ~91%   | 最快     |

**系统响应性能**：

- ⚡ 单样本检测：< 1秒
- ⚡ 批量检测（100条）：< 10秒
- ⚡ 模型加载时间：< 5秒

*注：实际性能可能因数据分布、硬件配置和参数设置而有所不同*

## 常见问题

### Q1: 内存不足怎么办？

**A**: 可以在 `data_preprocessing.py` 中对数据进行采样：

```python
# 在 load_datasets 函数中添加采样
train_df = train_df.sample(frac=0.5, random_state=42)  # 使用50%数据
```

### Q2: 训练时间太长？

**A**: 

1. 减少模型参数（如 `n_estimators`）
2. 使用数据采样
3. 只训练一个模型（如Random Forest）

### Q3: 如何添加新模型？

**A**: 在 `train_models.py` 的 `train_binary_classification` 方法中添加：

```python
models_config['YourModel'] = YourClassifier(...)
```

### Q4: 预测结果不准确？

**A**: 

1. 确保输入数据包含所有30个特征
2. 检查特征值是否在合理范围内
3. 确保使用正确的预处理器

## 检测与分析功能详解

### 威胁评分系统

系统采用多维度威胁评分机制（0-100分），综合考虑：

- **基础威胁得分**：基于攻击类型的威胁等级（0-50分）
- **特征异常得分**：基于异常网络特征的检测（0-30分）
- **风险指标得分**：基于高风险行为模式的识别（0-20分）

威胁等级划分：

- **严重** (80-100分)：需要立即采取行动
- **高** (60-79分)：需要尽快处理
- **中** (40-59分)：需要关注
- **低** (20-39分)：建议监控
- **正常** (0-19分)：无需处理

### 检测报告内容

生成的检测报告包含：

1. **检测结果**：类型、置信度、攻击类型
2. **威胁分析**：威胁得分、威胁等级、异常特征、风险指标
3. **攻击描述**：详细的攻击类型说明
4. **处理建议**：针对性的安全建议

### 历史分析功能

支持对检测历史进行统计分析：

- 攻击率统计
- 攻击类型分布
- 威胁等级分布
- 威胁得分统计（均值、最大值、最小值、标准差）

## 扩展建议

1. **特征工程**：
   - 尝试不同的特征组合
   - 添加交互特征
   - 使用深度学习进行特征提取

2. **模型优化**：
   - 超参数调优（GridSearch/RandomSearch）
   - 集成学习（Stacking/Voting）
   - 深度学习模型（LSTM/CNN）

3. **实时检测**：
   - 部署为Web服务（Flask/FastAPI）
   - 流式数据处理
   - 在线学习

4. **增强分析功能**：
   - 攻击路径分析
   - 攻击时间序列分析
   - 攻击关联分析
   - 自动化响应机制

## 参考资源

- [UNSW-NB15数据集官网](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- [scikit-learn文档](https://scikit-learn.org/)
- [XGBoost文档](https://xgboost.readthedocs.io/)
- [LightGBM文档](https://lightgbm.readthedocs.io/)

## 许可证

本项目仅用于学习和研究目的。

## 贡献

欢迎提交Issue和Pull Request！

---

**注意**: 本项目基于已有的特征选择结果。如果需要进行特征选择，请先运行 `feature_selection_statistical.py`。

