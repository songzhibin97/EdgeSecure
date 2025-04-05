GO_VERSION := 1.21
DOCKER_TAG := latest
NETWORK := edgesecure-net

GOOS := linux
GOARCH := arm
GOARM := 7
CGO_ENABLED := 0

BUILD_DIR := build
DIST_DIR := dist

CLIENT_APP := edgesecure
CLIENT_DOCKER_IMAGE := edgesecure
CLIENT_DOCKER_FILE := Dockerfile.client

SERVER_APP := mtlsserver
SERVER_DOCKER_IMAGE := edgesecure-server
SERVER_DOCKER_FILE := Dockerfile.server

.PHONY: all clean create-network build-client build-server create-client-dockerfile create-server-dockerfile docker-build-client docker-build-server docker-compose-up docker-compose-down

all: clean build-client build-server docker-build-client docker-build-server

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(CLIENT_DOCKER_FILE) $(SERVER_DOCKER_FILE)
	-docker network rm $(NETWORK)
	-docker rmi -f $(CLIENT_DOCKER_IMAGE):$(DOCKER_TAG) $(SERVER_DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	mkdir -p $(BUILD_DIR) $(DIST_DIR)

create-network:
	-docker network create $(NETWORK)

build-client:
	@echo "Building client ARM binary..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=$(CGO_ENABLED) go build \
		-ldflags="-s -w" \
		-o $(BUILD_DIR)/$(CLIENT_APP) \
		./cmd/$(CLIENT_APP)
	@echo "Client binary built at $(BUILD_DIR)/$(CLIENT_APP)"

build-server:
	@echo "Building mTLS server ARM binary..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=$(CGO_ENABLED) go build \
		-ldflags="-s -w" \
		-o $(BUILD_DIR)/$(SERVER_APP) \
		./cmd/$(SERVER_APP)
	@echo "Server binary built at $(BUILD_DIR)/$(SERVER_APP)"

create-server-dockerfile:
	@echo "Creating Dockerfile for server..."
	@echo "FROM golang:$(GO_VERSION)-alpine AS builder" > $(SERVER_DOCKER_FILE)
	@echo "WORKDIR /app" >> $(SERVER_DOCKER_FILE)
	@echo "COPY . ." >> $(SERVER_DOCKER_FILE)
	@echo "RUN go mod tidy" >> $(SERVER_DOCKER_FILE)
	@echo "RUN GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=$(CGO_ENABLED) go build -o $(SERVER_APP) ./cmd/$(SERVER_APP)" >> $(SERVER_DOCKER_FILE)
	@echo "FROM alpine:latest" >> $(SERVER_DOCKER_FILE)
	@echo "WORKDIR /app" >> $(SERVER_DOCKER_FILE)
	@echo "COPY --from=builder /app/$(SERVER_APP) ." >> $(SERVER_DOCKER_FILE)
	@echo "COPY config /app/config" >> $(SERVER_DOCKER_FILE)
	@echo "RUN apk add --no-cache curl ca-certificates netcat-openbsd" >> $(SERVER_DOCKER_FILE) # 添加netcat
	@echo "ENTRYPOINT [\"./$(SERVER_APP)\"]" >> $(SERVER_DOCKER_FILE)
	@echo "Dockerfile created at $(SERVER_DOCKER_FILE)"

create-client-dockerfile:
	@echo "Creating Dockerfile for client..."
	@echo "FROM golang:$(GO_VERSION)-alpine AS builder" > $(CLIENT_DOCKER_FILE)
	@echo "WORKDIR /app" >> $(CLIENT_DOCKER_FILE)
	@echo "COPY . ." >> $(CLIENT_DOCKER_FILE)
	@echo "RUN go mod tidy" >> $(CLIENT_DOCKER_FILE)
	@echo "RUN GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) CGO_ENABLED=$(CGO_ENABLED) go build -o $(CLIENT_APP) ./cmd/$(CLIENT_APP)" >> $(CLIENT_DOCKER_FILE)
	@echo "FROM alpine:latest" >> $(CLIENT_DOCKER_FILE)
	@echo "WORKDIR /app" >> $(CLIENT_DOCKER_FILE)
	@echo "COPY --from=builder /app/$(CLIENT_APP) ." >> $(CLIENT_DOCKER_FILE)
	@echo "COPY config /app/config" >> $(CLIENT_DOCKER_FILE)
	@echo "RUN apk add --no-cache curl ca-certificates" >> $(CLIENT_DOCKER_FILE) # 添加ca-certificates
	@echo "ENTRYPOINT [\"./$(CLIENT_APP)\"]" >> $(CLIENT_DOCKER_FILE)
	@echo "Dockerfile created at $(CLIENT_DOCKER_FILE)"

docker-build-client: build-client create-client-dockerfile
	@echo "Building Docker image for client..."
	docker build -t $(CLIENT_DOCKER_IMAGE):$(DOCKER_TAG) -f $(CLIENT_DOCKER_FILE) .
	@echo "Docker image $(CLIENT_DOCKER_IMAGE):$(DOCKER_TAG) built successfully"

docker-build-server: build-server create-server-dockerfile
	@echo "Building Docker image for server..."
	docker build -t $(SERVER_DOCKER_IMAGE):$(DOCKER_TAG) -f $(SERVER_DOCKER_FILE) .
	@echo "Docker image $(SERVER_DOCKER_IMAGE):$(DOCKER_TAG) built successfully"

docker-compose-up: docker-build-client docker-build-server
	@echo "Starting services with docker-compose..."
	docker-compose up --build

docker-compose-down:
	@echo "Stopping services and cleaning up..."
	docker-compose down --volumes

.PHONY: help
help:
	@echo "EdgeSecure Makefile Help"
	@echo "------------------------"
	@echo "  all               : Build client and server"
	@echo "  clean             : Remove build artifacts and network"
	@echo "  build-client      : Build client ARM binary"
	@echo "  build-server      : Build server ARM binary"
	@echo "  docker-build-client : Build client Docker image"
	@echo "  docker-build-server : Build server Docker image"
	@echo "  docker-compose-up : Start services with docker-compose"
	@echo "  docker-compose-down : Stop services and clean up"
	@echo "  help              : Show this help message"