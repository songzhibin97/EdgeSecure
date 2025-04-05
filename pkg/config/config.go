package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/songzhibin97/EdgeSecure/pkg/log"
	"gopkg.in/yaml.v2"
)

// Config 定义应用程序的配置结构
type Config struct {
	DataDir      string `json:"data_dir" yaml:"data_dir"`
	ClientDomain string `json:"client_domain" yaml:"client_domain"`
	ServerAddr   string `json:"server_addr" yaml:"server_addr"`
	ServerDomain string `json:"server_domain" yaml:"server_domain"`
	Port         string `json:"port" yaml:"port"`           // HTTPS端口
	HttpPort     string `json:"http_port" yaml:"http_port"` // HTTP端口
	LogLevel     string `json:"log_level" yaml:"log_level"`
}

// LoadConfig 加载配置，按照优先级：命令行 > 环境变量 > 配置文件
func LoadConfig(configFile string) (*Config, error) {
	cfg := &Config{
		DataDir:  "./data", // 默认值
		Port:     "8443",   // 默认HTTPS端口
		HttpPort: "8080",   // 默认HTTP端口
		LogLevel: "info",   // 默认值
	}

	// 1. 尝试加载配置文件
	if configFile != "" {
		if err := loadFile(configFile, cfg); err != nil {
			return nil, fmt.Errorf("failed to load config file: %v", err)
		}
	}

	// 2. 覆盖环境变量
	applyEnvVars(cfg)

	// 3. 覆盖命令行参数
	applyFlags(cfg)

	// 日志初始化（必须在配置加载后）
	log.Init(cfg.LogLevel)

	return cfg, nil
}

// loadFile 从JSON或YAML文件加载配置
func loadFile(filename string, cfg *Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	switch {
	case strings.HasSuffix(filename, ".json"):
		if err := json.Unmarshal(data, cfg); err != nil {
			return err
		}
	case strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml"):
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", filename)
	}

	log.Info("Loaded config from file", "file", filename)
	return nil
}

// applyEnvVars 从环境变量覆盖配置
func applyEnvVars(cfg *Config) {
	if val := os.Getenv("DATA_DIR"); val != "" {
		cfg.DataDir = val
	}
	if val := os.Getenv("CLIENT_DOMAIN"); val != "" {
		cfg.ClientDomain = val
	}
	if val := os.Getenv("SERVER_ADDR"); val != "" {
		cfg.ServerAddr = val
	}
	if val := os.Getenv("SERVER_DOMAIN"); val != "" {
		cfg.ServerDomain = val
	}
	if val := os.Getenv("PORT"); val != "" {
		cfg.Port = val
	}
	if val := os.Getenv("HTTP_PORT"); val != "" {
		cfg.HttpPort = val
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}
}

// applyFlags 从命令行参数覆盖配置
func applyFlags(cfg *Config) {
	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "Directory for data storage")
	flag.StringVar(&cfg.ClientDomain, "client-domain", cfg.ClientDomain, "Client domain for Let’s Encrypt")
	flag.StringVar(&cfg.ServerAddr, "server-addr", cfg.ServerAddr, "Server address (e.g., server.example.com:8443)")
	flag.StringVar(&cfg.ServerDomain, "server-domain", cfg.ServerDomain, "Server domain for Let’s Encrypt")
	flag.StringVar(&cfg.Port, "port", cfg.Port, "HTTPS port to listen on")
	flag.StringVar(&cfg.HttpPort, "http-port", cfg.HttpPort, "HTTP port for initial certificate distribution")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	flag.Parse()
}
