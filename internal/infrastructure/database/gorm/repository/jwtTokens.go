package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"
	"time"

	"gorm.io/gorm"
)

type JwtRepository struct {
	db *gorm.DB
}

func NewJwtRepository(db *gorm.DB) *JwtRepository {
	return &JwtRepository{
		db: db,
	}
}

func (j *JwtRepository) Create(ctx context.Context, token models.Token) (*models.Token, error) {
	gormToken := gormMappers.JwtToGormModel(token)
	err := j.db.WithContext(ctx).Create(&gormToken).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	return &token, nil
}

func (j *JwtRepository) Find(ctx context.Context, userId uint, refreshToken string) (*models.Token, error) {
	var gormToken gormModels.Token
	if err := j.db.WithContext(ctx).Where("user_id = ? AND refresh_token_hash = ? AND is_revoked = ?", userId, refreshToken, false).First(&gormToken).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	token := gormMappers.GormJwtToDomainModel(gormToken)
	return &token, nil
}

func (j *JwtRepository) Revoke(ctx context.Context, userId uint, refreshToken string) error {
	if err := j.db.WithContext(ctx).Model(&gormModels.Token{}).Where("user_id = ? AND refresh_token_hash = ? AND is_revoked = ?", userId, refreshToken, false).Updates(map[string]interface{}{
		"last_used":  time.Now(),
		"is_revoked": true,
	}).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil

}
