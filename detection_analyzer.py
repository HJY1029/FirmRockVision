#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统 - 检测与分析模块
提供详细的威胁检测、分析和报告生成功能
"""

import pandas as pd
import numpy as np
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
import warnings
from collections import Counter, defaultdict

from predict import IDSPredictor

warnings.filterwarnings('ignore')


class ThreatAnalyzer:
    """威胁分析器 - 提供详细的攻击特征分析"""
    
    # 攻击类型威胁等级映射
    THREAT_LEVELS = {
        'Normal': 0,
        'Fuzzers': 3,          # 中等威胁
        'Analysis': 4,         # 较高威胁
        'Backdoors': 5,        # 高威胁
        'DoS': 5,              # 高威胁
        'Exploits': 5,         # 高威胁
        'Generic': 2,          # 低威胁
        'Reconnaissance': 4,   # 较高威胁
        'Shellcode': 5,        # 高威胁
        'Worms': 5             # 高威胁
    }
    
    # 攻击类型描述
    ATTACK_DESCRIPTIONS = {
        'Normal': '正常网络流量',
        'Fuzzers': '模糊测试攻击 - 通过发送随机或异常数据来发现软件漏洞',
        'Analysis': '分析攻击 - 扫描和探测网络以收集信息',
        'Backdoors': '后门攻击 - 在系统中创建未授权访问通道',
        'DoS': '拒绝服务攻击 - 通过大量请求使服务不可用',
        'Exploits': '漏洞利用攻击 - 利用已知漏洞进行攻击',
        'Generic': '通用攻击 - 常见的网络攻击模式',
        'Reconnaissance': '侦察攻击 - 收集目标系统信息',
        'Shellcode': 'Shellcode攻击 - 执行恶意代码',
        'Worms': '蠕虫攻击 - 自我复制的恶意软件'
    }
    
    def __init__(self):
        """初始化威胁分析器"""
        self.feature_importance = self._load_feature_importance()
    
    def _load_feature_importance(self) -> Dict[str, float]:
        """加载特征重要性（基于特征选择结果）"""
        # 基于互信息得分的特征重要性（从高到低）
        importance_map = {
            'sttl': 0.15,
            'sbytes': 0.12,
            'ct_state_ttl': 0.10,
            'sload': 0.08,
            'smean': 0.07,
            'dttl': 0.06,
            'dbytes': 0.06,
            'dmean': 0.05,
            'dur': 0.05,
            'dload': 0.04,
            'dinpkt': 0.03,
            'dpkts': 0.03,
            'state': 0.02,
            'sinpkt': 0.02,
            'ct_dst_sport_ltm': 0.02,
            'spkts': 0.02,
            'ct_src_dport_ltm': 0.01,
            'swin': 0.01,
            'dwin': 0.01,
            'ct_dst_src_ltm': 0.01,
            'djit': 0.01,
            'sjit': 0.01,
            'ct_dst_ltm': 0.01,
            'dloss': 0.01,
            'ct_srv_dst': 0.01,
            'ct_src_ltm': 0.01,
            'sloss': 0.01,
            'ct_srv_src': 0.01,
            'proto': 0.01,
            'dtcpb': 0.01,
        }
        return importance_map
    
    def analyze_threat_features(self, data: Dict, prediction_result: Dict) -> Dict:
        """
        分析威胁特征
        
        Args:
            data: 原始数据字典
            prediction_result: 预测结果
            
        Returns:
            威胁特征分析字典
        """
        analysis = {
            'anomalous_features': [],
            'feature_scores': {},
            'risk_indicators': []
        }
        
        # 分析异常特征
        for feature, importance in self.feature_importance.items():
            if feature in data:
                value = data[feature]
                score = self._calculate_feature_risk_score(feature, value, importance)
                analysis['feature_scores'][feature] = {
                    'value': float(value) if isinstance(value, (int, float, np.number)) else str(value),
                    'importance': importance,
                    'risk_score': score
                }
                
                # 标记高风险特征
                if score > 0.7:
                    analysis['anomalous_features'].append({
                        'feature': feature,
                        'value': value,
                        'risk_score': score,
                        'description': self._get_feature_description(feature)
                    })
        
        # 生成风险指标
        analysis['risk_indicators'] = self._generate_risk_indicators(data, prediction_result)
        
        return analysis
    
    def _calculate_feature_risk_score(self, feature: str, value: Union[int, float], importance: float) -> float:
        """计算特征风险得分"""
        # 基于特征值的异常程度和重要性计算风险得分
        risk_score = 0.0
        
        # 检查极端值
        if isinstance(value, (int, float, np.number)):
            # 对于数值特征，检查是否在异常范围
            if feature in ['sbytes', 'dbytes']:
                # 字节数异常大或异常小都可能表示攻击
                if value > 1000000 or value < 0:
                    risk_score += 0.4
            elif feature in ['dur']:
                # 持续时间异常
                if value > 1000 or value < 0:
                    risk_score += 0.3
            elif feature in ['sttl', 'dttl']:
                # TTL值异常
                if value < 0 or value > 255:
                    risk_score += 0.5
            elif feature in ['sload', 'dload']:
                # 负载异常
                if value > 1000000000:
                    risk_score += 0.4
        
        # 结合特征重要性
        risk_score = min(1.0, risk_score * (1 + importance))
        
        return risk_score
    
    def _get_feature_description(self, feature: str) -> str:
        """获取特征描述"""
        descriptions = {
            'sttl': '源端TTL值 - 异常值可能表示IP欺骗',
            'sbytes': '源端字节数 - 异常大可能表示数据泄露或DDoS',
            'dbytes': '目标端字节数 - 异常大可能表示数据泄露',
            'dur': '连接持续时间 - 异常短可能表示扫描攻击',
            'sload': '源端负载 - 异常高可能表示DDoS攻击',
            'dload': '目标端负载 - 异常高可能表示DDoS攻击',
            'ct_state_ttl': '状态-TTL统计 - 异常可能表示网络扫描',
            'spkts': '源端包数 - 异常多可能表示洪水攻击',
            'dpkts': '目标端包数 - 异常多可能表示洪水攻击',
        }
        return descriptions.get(feature, f'{feature}特征异常')
    
    def _generate_risk_indicators(self, data: Dict, prediction_result: Dict) -> List[Dict]:
        """生成风险指标"""
        indicators = []
        
        # 检查各种风险指标
        if 'sbytes' in data and data['sbytes'] > 1000000:
            indicators.append({
                'type': 'high_bandwidth',
                'severity': 'high',
                'description': '检测到异常高的源端字节数，可能表示数据泄露或DDoS攻击'
            })
        
        if 'dur' in data and data['dur'] < 0.001:
            indicators.append({
                'type': 'short_duration',
                'severity': 'medium',
                'description': '连接持续时间异常短，可能表示扫描攻击'
            })
        
        if 'sttl' in data and (data['sttl'] < 0 or data['sttl'] > 255):
            indicators.append({
                'type': 'invalid_ttl',
                'severity': 'high',
                'description': 'TTL值异常，可能表示IP欺骗或网络异常'
            })
        
        if prediction_result.get('confidence', 0) < 0.6:
            indicators.append({
                'type': 'low_confidence',
                'severity': 'medium',
                'description': '模型预测置信度较低，建议人工审核'
            })
        
        return indicators
    
    def calculate_threat_score(self, prediction_result: Dict, threat_features: Dict) -> float:
        """
        计算综合威胁得分 (0-100)
        
        Args:
            prediction_result: 预测结果
            threat_features: 威胁特征分析
            
        Returns:
            威胁得分 (0-100)
        """
        score = 0.0
        debug_info = {}  # 用于调试
        
        # 判断是否为攻击：检查label、prediction类型或攻击概率
        is_attack = False
        label = prediction_result.get('label', 0)
        pred_type = prediction_result.get('prediction', '')
        
        # 获取攻击概率
        attack_prob = prediction_result.get('probability_attack', 0)
        if attack_prob == 0 and 'probability_normal' in prediction_result:
            attack_prob = 1.0 - prediction_result.get('probability_normal', 0)
        
        # 判断是否为攻击：label=1 或 prediction='攻击' 或 攻击概率>50%
        if label == 1 or pred_type == '攻击' or attack_prob > 0.5:
            is_attack = True
        
        debug_info['label'] = label
        debug_info['prediction_type'] = pred_type
        debug_info['attack_prob'] = attack_prob
        debug_info['is_attack'] = is_attack
        
        # 如果不是攻击，直接返回0分
        if not is_attack:
            debug_info['type'] = '正常'
            debug_info['final_score'] = 0.0
            return 0.0
        
        # 攻击样本的威胁得分计算
        attack_type = prediction_result.get('attack_type', 'Generic')
        threat_level = self.THREAT_LEVELS.get(attack_type, 3)
        
        # 1. 基础得分：基于攻击类型的威胁等级（40-60分）
        # 威胁等级越高，基础得分越高
        base_score = 40 + (threat_level * 4)  # 威胁等级3→52分，4→56分，5→60分
        score += base_score
        debug_info['base_score'] = base_score
        debug_info['attack_type'] = attack_type
        debug_info['threat_level'] = threat_level
        
        # 2. 置信度加成：使用攻击概率（最多+25分）
        # 使用之前获取的攻击概率
        confidence = attack_prob if attack_prob > 0 else prediction_result.get('confidence', 0.5)
        # 如果confidence是正常概率，转换为攻击概率
        if confidence < 0.5 and 'probability_normal' in prediction_result:
            confidence = 1.0 - prediction_result.get('probability_normal', 1.0 - confidence)
        
        debug_info['confidence'] = confidence
        
        # 置信度加成：高置信度大幅增加得分
        # 置信度0.5→0分，0.6→+5分，0.7→+10分，0.8→+15分，0.9→+20分，1.0→+25分
        confidence_bonus = (confidence - 0.5) * 50  # 最多+25分，最少-25分（但不会低于最低得分）
        score += confidence_bonus
        debug_info['confidence_bonus'] = confidence_bonus
        
        # 3. 特征异常得分（最多+20分）
        if threat_features.get('anomalous_features'):
            anomaly_score = sum([f['risk_score'] for f in threat_features['anomalous_features']])
            anomaly_score = min(20, anomaly_score * 10)  # 最多20分
            score += anomaly_score
            debug_info['anomaly_score'] = anomaly_score
            debug_info['anomalous_features_count'] = len(threat_features['anomalous_features'])
        else:
            debug_info['anomaly_score'] = 0
            debug_info['anomalous_features_count'] = 0
        
        # 4. 风险指标得分（最多+10分）
        risk_indicators = threat_features.get('risk_indicators', [])
        risk_score = 0
        for indicator in risk_indicators:
            if indicator['severity'] == 'high':
                risk_score += 5
            elif indicator['severity'] == 'medium':
                risk_score += 2
        risk_score = min(10, risk_score)  # 最多10分
        score += risk_score
        debug_info['risk_indicators_score'] = risk_score
        debug_info['risk_indicators_count'] = len(risk_indicators)
        
        # 5. 确保攻击样本至少有最低得分（基于攻击类型）
        # 高威胁攻击（等级5）至少60分，中威胁（等级4）至少55分，低威胁（等级3）至少50分
        min_score = 40 + (threat_level * 4)  # 等级3→52分，等级4→56分，等级5→60分
        original_score = score
        score = max(score, min_score)
        if score != original_score:
            debug_info['min_score_applied'] = min_score
        
        debug_info['final_score'] = score
        
        # 打印调试信息
        print(f"\n[威胁得分计算] 攻击类型: {debug_info.get('attack_type', 'Unknown')}")
        print(f"  基础得分: {debug_info.get('base_score', 0)}")
        print(f"  置信度: {debug_info.get('confidence', 0):.4f}")
        print(f"  置信度加成: {debug_info.get('confidence_bonus', 0):.2f}")
        print(f"  异常特征得分: {debug_info.get('anomaly_score', 0):.2f} ({debug_info.get('anomalous_features_count', 0)}个异常特征)")
        print(f"  风险指标得分: {debug_info.get('risk_indicators_score', 0):.2f} ({debug_info.get('risk_indicators_count', 0)}个风险指标)")
        if 'min_score_applied' in debug_info:
            print(f"  应用最低得分: {debug_info['min_score_applied']}")
        print(f"  最终得分: {debug_info['final_score']:.2f}")
        
        return min(100, max(0, score))
    
    def get_threat_level(self, threat_score: float) -> str:
        """根据威胁得分获取威胁等级"""
        if threat_score >= 80:
            return '严重'
        elif threat_score >= 60:
            return '高'
        elif threat_score >= 40:
            return '中'
        elif threat_score >= 20:
            return '低'
        else:
            return '正常'


class DetectionAnalyzer:
    """检测分析器 - 提供完整的检测和分析功能"""
    
    def __init__(self, models_dir='models', preprocessor_path='processed_data/preprocessor.pkl'):
        """
        初始化检测分析器
        
        Args:
            models_dir: 模型目录
            preprocessor_path: 预处理器路径
        """
        self.predictor = IDSPredictor(models_dir, preprocessor_path)
        self.threat_analyzer = ThreatAnalyzer()
        self.detection_history = []
    
    def detect_and_analyze(self, data: Union[Dict, pd.DataFrame], 
                          model_name: Optional[str] = None,
                          save_history: bool = True,
                          threshold: float = 0.3) -> Dict:
        """
        检测并分析网络流量
        
        Args:
            data: 输入数据（字典或DataFrame）
            model_name: 模型名称
            save_history: 是否保存到历史记录
            threshold: 预测阈值，攻击概率 >= threshold 时预测为攻击（默认0.3，更敏感）
            
        Returns:
            完整的检测分析结果
        """
        # 转换数据格式
        if isinstance(data, dict):
            data_df = pd.DataFrame([data])
        else:
            data_df = data.copy()
        
        # 预测（使用更低的阈值以提高检测敏感度）
        prediction_result = self.predictor.predict(data, model_name, threshold=threshold)
        
        # 如果是批量预测，处理每个结果
        if isinstance(prediction_result, list):
            results = []
            for i, pred in enumerate(prediction_result):
                sample_data = data_df.iloc[i].to_dict() if isinstance(data_df, pd.DataFrame) else data
                result = self._analyze_single_sample(sample_data, pred)
                results.append(result)
            
            if save_history:
                self.detection_history.extend(results)
            
            return {
                'batch_results': results,
                'summary': self._generate_batch_summary(results),
                'timestamp': datetime.now().isoformat()
            }
        else:
            # 单样本分析
            sample_data = data_df.iloc[0].to_dict() if isinstance(data_df, pd.DataFrame) else data
            result = self._analyze_single_sample(sample_data, prediction_result)
            
            if save_history:
                self.detection_history.append(result)
            
            return result
    
    def _analyze_single_sample(self, data: Dict, prediction_result: Dict) -> Dict:
        """分析单个样本"""
        # 调试：打印预测结果信息
        print(f"\n[_analyze_single_sample] 开始分析样本")
        print(f"  label: {prediction_result.get('label')}")
        print(f"  attack_type: {prediction_result.get('attack_type')}")
        print(f"  confidence: {prediction_result.get('confidence')}")
        print(f"  probability_attack: {prediction_result.get('probability_attack', 'N/A')}")
        print(f"  probability_normal: {prediction_result.get('probability_normal', 'N/A')}")
        print(f"  prediction_result keys: {list(prediction_result.keys())}")
        
        # 威胁特征分析
        threat_features = self.threat_analyzer.analyze_threat_features(data, prediction_result)
        
        # 计算威胁得分
        threat_score = self.threat_analyzer.calculate_threat_score(prediction_result, threat_features)
        threat_level = self.threat_analyzer.get_threat_level(threat_score)
        
        print(f"  [最终结果] 威胁得分: {threat_score:.2f}, 威胁等级: {threat_level}")
        
        # 构建完整结果
        # 确保概率信息被正确传递
        probabilities = prediction_result.get('probabilities', {})
        if not probabilities:
            # 如果probabilities为空，尝试从prediction_result中直接获取
            if 'probability_normal' in prediction_result:
                probabilities['probability_normal'] = prediction_result['probability_normal']
            if 'probability_attack' in prediction_result:
                probabilities['probability_attack'] = prediction_result['probability_attack']
        
        # 保存原始样本数据（特征值）
        # 将数据转换为可序列化的格式
        sample_features = {}
        for key, value in data.items():
            # 处理numpy类型和pandas类型
            if hasattr(value, 'item'):  # numpy标量
                sample_features[key] = float(value.item()) if hasattr(value, 'item') else float(value)
            elif pd.isna(value):
                sample_features[key] = None
            else:
                try:
                    # 尝试转换为基本类型
                    sample_features[key] = float(value) if isinstance(value, (int, float)) else str(value)
                except (ValueError, TypeError):
                    sample_features[key] = str(value)
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'sample_features': sample_features,  # 保存原始样本特征
            'prediction': {
                'type': prediction_result.get('prediction', '未知'),
                'label': prediction_result.get('label', 0),
                'confidence': prediction_result.get('confidence', 0.0),
                'attack_type': prediction_result.get('attack_type', None),
                'probabilities': probabilities,
                # 同时保留直接访问方式
                'probability_normal': prediction_result.get('probability_normal', probabilities.get('probability_normal', 0)),
                'probability_attack': prediction_result.get('probability_attack', probabilities.get('probability_attack', 0))
            },
            'threat_analysis': {
                'threat_score': round(threat_score, 2),
                'threat_level': threat_level,
                'anomalous_features': threat_features.get('anomalous_features', []),
                'risk_indicators': threat_features.get('risk_indicators', []),
                'feature_scores': threat_features.get('feature_scores', {})
            },
            'attack_description': self._get_attack_description(prediction_result),
            'recommendations': self._generate_recommendations(prediction_result, threat_score)
        }
        
        return result
    
    def _get_attack_description(self, prediction_result: Dict) -> str:
        """获取攻击描述"""
        attack_type = prediction_result.get('attack_type')
        if attack_type:
            return ThreatAnalyzer.ATTACK_DESCRIPTIONS.get(attack_type, '未知攻击类型')
        elif prediction_result.get('label') == 1:
            return '检测到网络攻击，但攻击类型未识别'
        else:
            return '正常网络流量'
    
    def _generate_recommendations(self, prediction_result: Dict, threat_score: float) -> List[str]:
        """生成建议"""
        recommendations = []
        
        # 判断是否为攻击：检查label、prediction类型或attack_type
        is_attack = False
        label = prediction_result.get('label', 0)
        pred_type = prediction_result.get('prediction', '')
        attack_type = prediction_result.get('attack_type')
        
        # 如果label=1 或 prediction='攻击' 或 有attack_type，则认为是攻击
        if label == 1 or pred_type == '攻击' or attack_type:
            is_attack = True
        
        if is_attack:
            attack_type = attack_type or 'Unknown'
            
            if attack_type == 'DoS':
                recommendations.append('🚨 立即检查服务器负载和网络带宽使用情况')
                recommendations.append('🚨 考虑启用DDoS防护服务')
                recommendations.append('🚨 检查是否有异常的大量连接请求')
                recommendations.append('🚨 考虑临时限制来自可疑IP的连接')
            
            elif attack_type == 'Backdoors':
                recommendations.append('🚨 立即检查系统是否有未授权的访问')
                recommendations.append('🚨 审查系统日志和网络连接')
                recommendations.append('🚨 检查是否有异常的后门进程或服务')
                recommendations.append('🚨 考虑进行全面的安全审计')
                recommendations.append('🚨 立即更改所有系统密码和密钥')
            
            elif attack_type == 'Exploits':
                recommendations.append('🚨 立即检查系统是否有未修补的漏洞')
                recommendations.append('🚨 更新系统和应用程序到最新版本')
                recommendations.append('🚨 审查异常的系统行为和日志')
                recommendations.append('🚨 检查是否有未授权的文件修改')
                recommendations.append('🚨 考虑隔离受影响的系统')
            
            elif attack_type == 'Reconnaissance':
                recommendations.append('⚠️ 监控网络扫描活动')
                recommendations.append('⚠️ 检查防火墙规则和访问控制列表')
                recommendations.append('⚠️ 加强网络访问控制')
                recommendations.append('⚠️ 记录并分析扫描来源IP')
                recommendations.append('⚠️ 考虑阻止可疑IP地址')
            
            elif attack_type == 'Shellcode':
                recommendations.append('🚨 立即检查系统是否有恶意代码执行')
                recommendations.append('🚨 审查进程列表和网络连接')
                recommendations.append('🚨 检查是否有异常的内存使用')
                recommendations.append('🚨 考虑进行恶意软件扫描')
                recommendations.append('🚨 隔离受影响的系统并深入调查')
            
            elif attack_type == 'Worms':
                recommendations.append('🚨 立即隔离受感染的系统')
                recommendations.append('🚨 检查网络中的其他系统是否被感染')
                recommendations.append('🚨 阻止蠕虫传播的网络端口')
                recommendations.append('🚨 更新防病毒软件和系统补丁')
                recommendations.append('🚨 进行全面的网络扫描和清理')
            
            elif attack_type == 'Fuzzers':
                recommendations.append('⚠️ 监控模糊测试活动')
                recommendations.append('⚠️ 检查系统日志中的异常输入')
                recommendations.append('⚠️ 加强输入验证和错误处理')
                recommendations.append('⚠️ 考虑限制来自可疑源的连接')
            
            elif attack_type == 'Analysis':
                recommendations.append('⚠️ 监控网络分析活动')
                recommendations.append('⚠️ 检查是否有端口扫描行为')
                recommendations.append('⚠️ 加强网络监控和日志记录')
                recommendations.append('⚠️ 考虑限制网络访问权限')
            
            else:
                recommendations.append('⚠️ 进一步分析网络流量特征')
                recommendations.append('⚠️ 检查系统日志和网络连接')
                recommendations.append('⚠️ 考虑隔离可疑流量')
                recommendations.append('⚠️ 进行深入的安全调查')
            
            # 根据威胁得分添加紧急程度提示
            if threat_score >= 80:
                recommendations.append('🔴 威胁等级严重，建议立即采取行动并通知安全团队')
            elif threat_score >= 60:
                recommendations.append('🟠 威胁等级较高，建议尽快处理并加强监控')
            elif threat_score >= 40:
                recommendations.append('🟡 威胁等级中等，建议关注并采取预防措施')
            else:
                recommendations.append('🟢 威胁等级较低，建议持续监控')
        
        else:
            recommendations.append('✅ 流量正常，无需采取行动')
            recommendations.append('✅ 建议继续监控网络流量')
        
        return recommendations
    
    def _generate_batch_summary(self, results: List[Dict]) -> Dict:
        """生成批量检测摘要"""
        total = len(results)
        if total == 0:
            return {
                'total_samples': 0,
                'normal_count': 0,
                'attack_count': 0,
                'attack_rate': 0,
                'attack_type_distribution': {},
                'avg_threat_score': 0,
                'max_threat_score': 0,
                'min_threat_score': 0
            }
        
        # 统计攻击和正常
        attacks = 0
        normal = 0
        attack_types = Counter()
        threat_scores = []
        high_risk_count = 0  # 高风险样本（攻击概率>30%但未分类为攻击）
        
        # 调试：打印前几个结果
        print(f"\n生成批量摘要: 共 {total} 个结果")
        for i, r in enumerate(results[:5]):  # 打印前5个
            pred = r.get('prediction', {})
            label = pred.get('label', -1)
            pred_type = pred.get('type', '未知')
            prob_attack = pred.get('probability_attack', 0)
            if prob_attack == 0:
                # 尝试从probabilities获取
                probs = pred.get('probabilities', {})
                if isinstance(probs, dict):
                    prob_attack = probs.get('probability_attack', 0)
            print(f"  样本 {i}: label={label}, type={pred_type}, "
                  f"攻击概率={prob_attack:.4f}, confidence={pred.get('confidence', 0):.3f}")
        
        for r in results:
            pred = r.get('prediction', {})
            label = pred.get('label', 0)
            
            # 获取攻击概率
            prob_attack = pred.get('probability_attack', 0)
            if prob_attack == 0:
                # 尝试从probabilities获取
                probs = pred.get('probabilities', {})
                if isinstance(probs, dict):
                    prob_attack = probs.get('probability_attack', 0)
                elif pred.get('label') == 0:
                    # 如果label=0，攻击概率 = 1 - confidence
                    prob_attack = 1.0 - pred.get('confidence', 0)
            
            # 如果攻击概率 > 30% 但 label=0，标记为高风险
            if label == 0 and prob_attack > 0.3:
                high_risk_count += 1
                print(f"  [警告] 样本攻击概率={prob_attack:.4f}但被分类为正常，可能存在误判")
            
            if label == 1:
                attacks += 1
                attack_type = pred.get('attack_type', 'Unknown')
                attack_types[attack_type] += 1
            else:
                normal += 1
            
            threat_score = r.get('threat_analysis', {}).get('threat_score', 0)
            threat_scores.append(threat_score)
        
        print(f"统计结果: 正常={normal}, 攻击={attacks}, 攻击率={round(attacks / total * 100, 2) if total > 0 else 0}%")
        if high_risk_count > 0:
            print(f"  [警告] 发现 {high_risk_count} 个高风险样本（攻击概率>30%但被分类为正常）")
        
        return {
            'total_samples': total,
            'normal_count': normal,
            'attack_count': attacks,
            'attack_rate': round(attacks / total * 100, 2) if total > 0 else 0,
            'attack_type_distribution': dict(attack_types),
            'avg_threat_score': round(np.mean(threat_scores), 2) if threat_scores else 0,
            'max_threat_score': round(max(threat_scores), 2) if threat_scores else 0,
            'min_threat_score': round(min(threat_scores), 2) if threat_scores else 0,
            'high_risk_count': high_risk_count  # 高风险样本数
        }
    
    def generate_report(self, result: Dict, output_path: Optional[str] = None) -> str:
        """
        生成检测报告
        
        Args:
            result: 检测分析结果
            output_path: 输出文件路径（可选）
            
        Returns:
            报告文本
        """
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(" " * 20 + "磐石之眼（FirmRock Vision）- 网络入侵检测分析报告")
        report_lines.append("=" * 80)
        report_lines.append(f"\n生成时间: {result.get('timestamp', 'N/A')}")
        report_lines.append("\n" + "-" * 80)
        
        # 预测结果
        pred = result['prediction']
        report_lines.append("\n【检测结果】")
        report_lines.append(f"  类型: {pred['type']}")
        report_lines.append(f"  置信度: {pred['confidence']:.4f} ({pred['confidence']*100:.2f}%)")
        
        if pred.get('attack_type'):
            report_lines.append(f"  攻击类型: {pred['attack_type']}")
            report_lines.append(f"  攻击描述: {result.get('attack_description', 'N/A')}")
        
        # 威胁分析
        threat = result['threat_analysis']
        report_lines.append("\n【威胁分析】")
        report_lines.append(f"  威胁得分: {threat['threat_score']}/100")
        report_lines.append(f"  威胁等级: {threat['threat_level']}")
        
        if threat.get('anomalous_features'):
            report_lines.append(f"\n  异常特征 ({len(threat['anomalous_features'])} 个):")
            for feat in threat['anomalous_features'][:5]:  # 只显示前5个
                report_lines.append(f"    - {feat['feature']}: {feat['value']} (风险得分: {feat['risk_score']:.2f})")
                report_lines.append(f"      描述: {feat['description']}")
        
        if threat.get('risk_indicators'):
            report_lines.append(f"\n  风险指标 ({len(threat['risk_indicators'])} 个):")
            for indicator in threat['risk_indicators']:
                severity_icon = '🔴' if indicator['severity'] == 'high' else '🟡'
                report_lines.append(f"    {severity_icon} [{indicator['severity'].upper()}] {indicator['description']}")
        
        # 建议
        if result.get('recommendations'):
            report_lines.append("\n【处理建议】")
            for i, rec in enumerate(result['recommendations'], 1):
                report_lines.append(f"  {i}. {rec}")
        
        report_lines.append("\n" + "=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # 保存到文件
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n报告已保存到: {output_path}")
        
        return report_text
    
    def analyze_history(self, days: Optional[int] = None) -> Dict:
        """
        分析检测历史
        
        Args:
            days: 分析最近N天的记录（None表示全部）
            
        Returns:
            历史分析结果
        """
        if not self.detection_history:
            return {'message': '暂无检测历史记录'}
        
        # 过滤时间范围
        history = self.detection_history
        if days:
            cutoff = datetime.now().timestamp() - days * 86400
            history = [h for h in history if datetime.fromisoformat(h['timestamp']).timestamp() > cutoff]
        
        if not history:
            return {'message': f'最近{days}天内无检测记录'}
        
        # 统计分析
        total = len(history)
        attacks = sum(1 for h in history if h['prediction']['label'] == 1)
        normal = total - attacks
        
        attack_types = Counter()
        threat_levels = Counter()
        threat_scores = []
        
        for h in history:
            if h['prediction']['label'] == 1:
                attack_type = h['prediction'].get('attack_type', 'Unknown')
                attack_types[attack_type] += 1
            threat_level = h['threat_analysis']['threat_level']
            threat_levels[threat_level] += 1
            threat_scores.append(h['threat_analysis']['threat_score'])
        
        return {
            'period': f'最近{days}天' if days else '全部',
            'total_detections': total,
            'normal_count': normal,
            'attack_count': attacks,
            'attack_rate': round(attacks / total * 100, 2) if total > 0 else 0,
            'attack_type_distribution': dict(attack_types),
            'threat_level_distribution': dict(threat_levels),
            'threat_score_stats': {
                'mean': round(np.mean(threat_scores), 2),
                'max': round(max(threat_scores), 2),
                'min': round(min(threat_scores), 2),
                'std': round(np.std(threat_scores), 2)
            }
        }
    
    def save_history(self, filepath: str = 'detection_history.json'):
        """保存检测历史到文件"""
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.detection_history, f, ensure_ascii=False, indent=2, default=str)
        
        print(f"检测历史已保存到: {output_path}")
    
    def load_history(self, filepath: str = 'detection_history.json'):
        """从文件加载检测历史"""
        input_path = Path(filepath)
        if input_path.exists():
            with open(input_path, 'r', encoding='utf-8') as f:
                self.detection_history = json.load(f)
            print(f"已加载 {len(self.detection_history)} 条检测历史记录")
        else:
            print(f"历史记录文件不存在: {input_path}")


def main():
    """主函数 - 示例用法"""
    print("\n" + "=" * 80)
    print(" " * 20 + "磐石之眼（FirmRock Vision）- 智能网络入侵检测与威胁分析系统")
    print("=" * 80)
    
    # 创建检测分析器
    analyzer = DetectionAnalyzer()
    
    if len(analyzer.predictor.models) == 0:
        print("\n错误: 没有可用的模型，请先运行 train_models.py")
        return
    
    print(f"\n已加载 {len(analyzer.predictor.models)} 个模型")
    
    # 示例：从测试集加载数据进行检测和分析
    test_data_path = Path('UNSW_NB15_testing-set.csv')
    if test_data_path.exists():
        print("\n从测试集加载示例数据进行检测和分析...")
        test_df = pd.read_csv(test_data_path, nrows=3)
        
        for idx, row in test_df.iterrows():
            print(f"\n{'='*80}")
            print(f"样本 {idx + 1} 检测分析")
            print(f"{'='*80}")
            
            # 检测和分析
            result = analyzer.detect_and_analyze(row)
            
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
            
            if result.get('recommendations'):
                print(f"\n处理建议:")
                for rec in result['recommendations']:
                    print(f"  - {rec}")
            
            # 生成报告
            report_path = f'reports/detection_report_sample_{idx+1}.txt'
            analyzer.generate_report(result, report_path)
        
        # 批量检测分析
        print(f"\n{'='*80}")
        print("批量检测分析")
        print(f"{'='*80}")
        batch_result = analyzer.detect_and_analyze(test_df.head(10))
        
        if 'summary' in batch_result:
            summary = batch_result['summary']
            print(f"\n批量检测摘要:")
            print(f"  总样本数: {summary['total_samples']}")
            print(f"  正常流量: {summary['normal_count']}")
            print(f"  攻击流量: {summary['attack_count']}")
            print(f"  攻击率: {summary['attack_rate']}%")
            print(f"  平均威胁得分: {summary['avg_threat_score']}")
            
            if summary.get('attack_type_distribution'):
                print(f"\n攻击类型分布:")
                for atype, count in summary['attack_type_distribution'].items():
                    print(f"  {atype}: {count}")
        
        # 保存历史记录
        analyzer.save_history()
        
    else:
        print("\n未找到测试数据文件，无法进行示例检测")
        print("\n使用示例:")
        print("""
        from detection_analyzer import DetectionAnalyzer
        
        analyzer = DetectionAnalyzer()
        
        # 单样本检测
        sample = {
            'sttl': 254,
            'sbytes': 496,
            # ... 其他特征
        }
        result = analyzer.detect_and_analyze(sample)
        
        # 生成报告
        analyzer.generate_report(result, 'report.txt')
        
        # 查看历史分析
        history = analyzer.analyze_history(days=7)
        print(history)
        """)


if __name__ == "__main__":
    main()

