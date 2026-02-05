package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func JwtToGormModel(jwt models.Token) gormModels.Token {
	return gormModels.Token{
		UserID:           uint(jwt.UserID),
		RefreshTokenHash: jwt.RefreshTokenHash,
		Device:           jwt.Device,
		IpAddress:        jwt.IpAddress,
		UserAgent:        jwt.UserAgent,
		IsRevoked:        jwt.IsRevoked,
		Expires:          jwt.Expires,
		LastUsed:         jwt.LastUsed,
	}
}

func GormJwtToDomainModel(jwtGorm gormModels.Token) models.Token {
	return models.Token{
		ID:               jwtGorm.ID,
		RefreshTokenHash: jwtGorm.RefreshTokenHash,
		Device:           jwtGorm.Device,
		IpAddress:        jwtGorm.IpAddress,
		UserAgent:        jwtGorm.UserAgent,
		IsRevoked:        jwtGorm.IsRevoked,
		Expires:          jwtGorm.Expires,
		LastUsed:         jwtGorm.LastUsed,
	}
}
