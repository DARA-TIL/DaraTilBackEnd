package utils

import (
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"encoding/json"
	"os"

	"go.uber.org/zap"
)

func ReadKzGeoJson() []dto.Region {
	b, err := os.ReadFile("internal/presentation/http/utils/kzGeo.json")
	if err != nil {
		logger.Error("Error reading ./kzGeo.json", zap.Error(err))
		return nil
	}
	var regions []dto.Region
	err = json.Unmarshal(b, &regions)
	if err != nil {
		logger.Error("Error reading ./kzGeo.json", zap.Error(err))
		return nil
	}
	logger.Info("Read KzGeoJson successfully", zap.Any("regions", regions))
	return regions
}
