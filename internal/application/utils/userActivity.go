package utils

import (
	"DaraTilBackendV2/internal/infrastructure/logger"

	"go.uber.org/zap"
)

func LoggerUserActivity(userID, entityID uint, entityType, act string) {
	logger.Info("Logging User Activity", zap.Uint("userID", userID), zap.String("entity", entityType), zap.Uint("EntityID", entityID), zap.String("activity", string(act)))
}
func ErrLoggerUserActivity(err error) {
	logger.Warn("Failed to log User Activity", zap.Error(err))
}
