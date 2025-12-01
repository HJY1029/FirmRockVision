# 磐石之眼（FirmRock Vision）- Docker镜像配置
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_ENV=production

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建必要的目录
RUN mkdir -p reports static templates uploads models processed_data

# 暴露端口
EXPOSE 5000

# 设置启动命令
CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "600", "--max-requests", "1000"]

