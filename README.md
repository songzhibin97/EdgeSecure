# EdgeSecure

EdgeSecure 是一个基于互助 TLS (mTLS) 的边缘设备安全通信系统。它包括一个服务器（`mtlsserver`）和一个客户端（`edgesecure-client`），通过自定义证书颁发机构（CA）签发的自签名证书建立安全连接。

## 功能
- **互助 TLS 认证**：服务器和客户端通过证书相互认证。
- **动态证书管理**：自动生成、续期和分发证书。
- **安全初始化**：通过 HTTP 进行初始证书分发，后续通信使用 mTLS。
- **Docker 支持**：使用 Docker Compose 轻松部署。

## 前提条件
- 已安装 Docker 和 Docker Compose。
- Go 1.18 或更高版本（用于从源码构建）。

## 目录结构
```
EdgeSecure/
├── cmd/
│   ├── edgesecure/    # 客户端应用程序
│   └── mtlsserver/    # 服务器应用程序
├── pkg/               # 共享包（cert、config、log 等）
├── data/              # 证书数据目录
│   ├── server/
│   └── client/
├── config/            # 配置文件
│   ├── server-config.yaml
│   └── client-config.yaml
├── Dockerfile.client  # edgesecure-client 的 Dockerfile
├── Dockerfile.server  # mtlsserver 的 Dockerfile
└── docker-compose.yml # Docker Compose 配置文件
```

## 快速开始
1. **克隆仓库**
   ```bash
   git clone <repository-url>
   cd EdgeSecure
   ```

2. **准备数据目录**
   ```bash
   mkdir -p data/server data/client
   chmod 755 data/server data/client
   ```

3. **使用 Docker Compose 运行**
   ```bash
   docker-compose up --build
   ```

4. **检查日志**
   ```bash
   docker-compose logs
   ```
   寻找成功的 mTLS 连接消息：
   ```
   edgesecure-client  | {"level":"INFO","msg":"TLS connection established","addr":"mtlsserver:8443"}
   mtlsserver         | {"level":"INFO","msg":"Client initialization complete, shutting down HTTP server"}
   ```

5. **停止服务**
   ```bash
   docker-compose down
   ```

## 配置

### 服务器配置 (server-config.yaml)
```yaml
data_dir: /app/data
server_domain: mtlsserver
port: "8443"
http_port: "8080"
log_level: info
```

### 客户端配置 (client-config.yaml)
```yaml
data_dir: /app/data
client_domain: edgesecure-client
server_addr: mtlsserver:8443
http_port: "8080"
log_level: info
```

## 安全注意事项
- HTTP 端点（/ca、/server-cert、/cert）用于初始证书分发，在客户端初始化完成后关闭。
- 后续所有通信通过 HTTPS 使用 mTLS。

## 故障排除
- **连接被拒绝**：确保 mtlsserver 正在运行且在 Docker 网络中可被 edgesecure-client 访问。
- **证书错误**：清除 data/ 目录并重启以重新生成证书。

## 贡献
欢迎提交问题或拉取请求以改进 EdgeSecure。

## 许可证
MIT 许可证