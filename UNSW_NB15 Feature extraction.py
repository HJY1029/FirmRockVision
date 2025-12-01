# ---------------------- 1. 导入依赖库 ----------------------
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler  # 特征标准化
from sklearn.decomposition import PCA  # 主成分分析（特征抽取）

# ---------------------- 2. 加载数据集 ----------------------
train_df = pd.read_csv("UNSW_NB15_training-set.csv")
test_df = pd.read_csv("UNSW_NB15_testing-set.csv")
df = pd.concat([train_df, test_df], axis=0, ignore_index=True)  # 合并数据集

# ---------------------- 3. 缺失值处理 ----------------------

# 步骤1：检查所有列的缺失值情况
print("===== 处理前：各列缺失值统计 =====")
missing_values = df.isnull().sum()
print(missing_values[missing_values > 0])  # 只显示有缺失的列


# 步骤2：定义分类列和数值列（根据UNSW数据集特点）
categorical_cols = ["proto", "service", "state"]  # 分类特征（字符串/离散类别）
numeric_cols = [col for col in df.columns if col not in categorical_cols + ["label", "attack_cat"]]  # 数值特征


# 步骤3：处理分类列的缺失值（众数填充）
for col in categorical_cols:
    col_mode = df[col].mode()[0]  # 计算众数
    df[col] = df[col].fillna(col_mode)  # 填充缺失值


# 步骤4：处理数值列的缺失值（中位数填充）
for col in numeric_cols:
    col_median = df[col].median()  # 计算中位数
    df[col] = df[col].fillna(col_median)  # 填充缺失值


# 步骤5：验证缺失值是否处理完毕
print("\n===== 处理后：各列缺失值统计 =====")
print(df.isnull().sum()[df.isnull().sum() > 0])  # 输出为空则处理完成


# ---------------------- 4. 分类特征编码（转为数值型，用于后续特征抽取） ----------------------
# 对分类列进行独热编码（将字符串类别转为0/1数值特征）
df_encoded = pd.get_dummies(df, columns=categorical_cols)
print(f"\n独热编码后特征数量：{df_encoded.shape[1]}（含标签列）")


# ---------------------- 5. 分离特征（X）和标签（y） ----------------------
# 特征：排除标签列（label为二分类标签，attack_cat为攻击类型多分类标签）
X = df_encoded.drop(["label", "attack_cat"], axis=1)
# 标签：使用二分类标签label（0=正常，1=异常）
y = df_encoded["label"]

print(f"特征矩阵形状（样本数, 特征数）：{X.shape}")
print(f"标签形状（样本数）：{y.shape}")


# ---------------------- 6. 特征标准化 ----------------------
# 将所有特征缩放到“均值=0，方差=1”，消除量纲影响
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)  # 拟合并转换特征矩阵

# 查看标准化后的特征均值（接近0）和方差（接近1），验证标准化效果
print(f"\n标准化后特征均值（示例）：{np.mean(X_scaled, axis=0)[:5].round(3)}")  # 前5个特征的均值
print(f"标准化后特征方差（示例）：{np.var(X_scaled, axis=0)[:5].round(3)}")  # 前5个特征的方差


# ---------------------- 7. 特征抽取（PCA主成分分析） ----------------------
# 初始化PCA：保留95%的方差（即保留原数据95%的信息）
pca = PCA(n_components=0.95, random_state=42)  # random_state确保结果可复现

# 对标准化后的特征进行PCA降维
X_pca = pca.fit_transform(X_scaled)

# 输出PCA结果分析
print("\n===== PCA特征抽取结果 =====")
print(f"原始特征数量：{X.shape[1]}")
print(f"PCA后特征数量（主成分数）：{X_pca.shape[1]}")
print(f"各主成分的方差占比（前5个）：{pca.explained_variance_ratio_[:5].round(4)}")  # 前5个主成分的信息占比
print(f"累计方差占比（总保留信息）：{np.cumsum(pca.explained_variance_ratio_)[-1].round(4)*100}%")  # 总保留信息比例


# ---------------------- 8. 保存处理后的特征和标签 ----------------------
# 将PCA后的特征和标签保存为CSV，方便后续建模使用
pca_df = pd.DataFrame(X_pca, columns=[f"PC{i+1}" for i in range(X_pca.shape[1])])  # 主成分列名
pca_df["label"] = y.values  # 加入标签列
pca_df.to_csv("UNSW_NB15_pca_features.csv", index=False)
print("\n已保存PCA特征到 UNSW_NB15_pca_features.csv")