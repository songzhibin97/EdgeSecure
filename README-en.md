# EdgeSecure

EdgeSecure is a mutual TLS (mTLS) based secure communication system designed for edge devices. It provides a server (`mtlsserver`) and a client (`edgesecure-client`) that establish a secure connection using self-signed certificates issued by a custom Certificate Authority (CA).

## Features
- **Mutual TLS Authentication**: Both server and client authenticate each other using certificates.
- **Dynamic Certificate Management**: Automatic generation, renewal, and distribution of certificates.
- **Secure Initialization**: Initial certificate distribution over HTTP, followed by mTLS for subsequent communication.
- **Docker Support**: Easy deployment with Docker Compose.

## Prerequisites
- Docker and Docker Compose installed.
- Go 1.18 or later (for building from source).

## Directory Structure
```
EdgeSecure/
├── cmd/
│   ├── edgesecure/    # Client application
│   └── mtlsserver/    # Server application
├── pkg/               # Shared packages (cert, config, log, etc.)
├── data/              # Data directory for certificates
│   ├── server/
│   └── client/
├── config/            # Configuration files
│   ├── server-config.yaml
│   └── client-config.yaml
├── Dockerfile.client  # Dockerfile for edgesecure-client
├── Dockerfile.server  # Dockerfile for mtlsserver
└── docker-compose.yml # Docker Compose configuration
```

## Quick Start
1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd EdgeSecure
   ```

2. **Prepare Data Directories**
   ```bash
   mkdir -p data/server data/client
   chmod 755 data/server data/client
   ```

3. **Run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

4. **Verify Logs**
   ```bash
   docker-compose logs
   ```
   Look for successful mTLS connection messages:
   ```
   edgesecure-client  | {"level":"INFO","msg":"TLS connection established","addr":"mtlsserver:8443"}
   mtlsserver         | {"level":"INFO","msg":"Client initialization complete, shutting down HTTP server"}
   ```

5. **Stop Services**
   ```bash
   docker-compose down
   ```

## Configuration

### Server Config (server-config.yaml)
```yaml
data_dir: /app/data
server_domain: mtlsserver
port: "8443"
http_port: "8080"
log_level: info
```

### Client Config (client-config.yaml)
```yaml
data_dir: /app/data
client_domain: edgesecure-client
server_addr: mtlsserver:8443
http_port: "8080"
log_level: info
```

## Security Notes
- HTTP endpoints (/ca, /server-cert, /cert) are used for initial certificate distribution and are shut down after client initialization.
- All subsequent communication uses mTLS over HTTPS.

## Troubleshooting
- **Connection Refused**: Ensure mtlsserver is running and reachable from edgesecure-client within the Docker network.
- **Certificate Errors**: Clear the data/ directory and restart to regenerate certificates.

## Contributing
Feel free to submit issues or pull requests to improve EdgeSecure.

## License
MIT License