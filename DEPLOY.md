# 快速部署指南

## 🚀 一键部署到云端

### 方法1: Railway（推荐，最简单）

1. 访问 https://railway.app
2. 使用GitHub登录
3. 点击 "New Project" → "Deploy from GitHub repo"
4. 选择您的仓库
5. 添加环境变量：
   - `FLASK_ENV=production`
   - `FLASK_DEBUG=False`
   - `SECRET_KEY=你的密钥`（使用 `python -c "import secrets; print(secrets.token_hex(32))"` 生成）
6. 等待部署完成

### 方法2: Render

1. 访问 https://render.com
2. 使用GitHub登录
3. 点击 "New +" → "Web Service"
4. 连接您的仓库
5. 配置：
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn wsgi:app --bind 0.0.0.0:$PORT`
6. 添加环境变量（同Railway）
7. 点击 "Create Web Service"

### 方法3: Docker

```bash
# 构建镜像
docker build -t firmrock-vision .

# 运行容器
docker run -d -p 5000:5000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY=你的密钥 \
  firmrock-vision
```

## 📋 部署前检查

运行检查脚本：

```bash
python check_deployment.py
```

## 📚 详细文档

查看 [云端部署指南.md](云端部署指南.md) 获取完整的部署说明。

## ⚠️ 重要提示

1. **确保模型已训练**：运行 `python main.py --step train`
2. **设置强SECRET_KEY**：不要使用默认值
3. **检查环境变量**：确保所有必需的环境变量已设置

