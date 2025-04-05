package log

import (
	"log/slog"
	"os"
	"sync"
)

var (
	logger *slog.Logger
	once   sync.Once
)

// 默认初始化，在包加载时设置一个Info级别的Logger
func init() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger = slog.New(handler)
}

// Init 初始化或替换全局Logger实例
func Init(level string) {
	once.Do(func() {
		var slogLevel slog.Level
		switch level {
		case "debug":
			slogLevel = slog.LevelDebug
		case "info":
			slogLevel = slog.LevelInfo
		case "warn":
			slogLevel = slog.LevelWarn
		case "error":
			slogLevel = slog.LevelError
		default:
			slogLevel = slog.LevelInfo
			// 使用默认logger输出警告
			logger.Warn("Invalid log level, defaulting to info", "input", level)
		}

		handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slogLevel,
		})
		logger = slog.New(handler)
	})
}

// Debug 记录调试级别日志
func Debug(msg string, args ...interface{}) {
	logger.Debug(msg, args...)
}

// Info 记录信息级别日志
func Info(msg string, args ...interface{}) {
	logger.Info(msg, args...)
}

// Warn 记录警告级别日志
func Warn(msg string, args ...interface{}) {
	logger.Warn(msg, args...)
}

// Error 记录错误级别日志
func Error(msg string, args ...interface{}) {
	logger.Error(msg, args...)
}
