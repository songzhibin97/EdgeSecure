FROM debian:buster-slim

# 设置工作目录
WORKDIR /app

# 复制交叉编译好的二进制文件
COPY build/edgesecure .

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN useradd -r -u 1000 -g root edgeuser
RUN chown -R edgeuser:root /app
USER edgeuser

# 运行EdgeSecure
CMD ["./edgesecure"]