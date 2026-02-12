package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.Logger

func Init(dev bool) {
	if dev {
		config := zap.Config{
			Level:       zap.NewAtomicLevelAt(zap.DebugLevel),
			Development: true,
			Encoding:    "console",
			EncoderConfig: zapcore.EncoderConfig{
				TimeKey:      "time",
				LevelKey:     "level",
				MessageKey:   "msg",
				CallerKey:    "caller",
				EncodeLevel:  zapcore.CapitalColorLevelEncoder,
				EncodeTime:   zapcore.ISO8601TimeEncoder,
				EncodeCaller: zapcore.ShortCallerEncoder,
			},
			OutputPaths:      []string{"stdout"},
			ErrorOutputPaths: []string{"stdout"},
		}

		log, _ = config.Build()
	} else {
		log, _ = zap.NewProduction()
	}
}
func Info(msg string, fields ...zap.Field) {
	log.Info(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	log.Error(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	log.Warn(msg, fields...)
}
