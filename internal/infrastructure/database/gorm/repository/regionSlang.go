package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionSlangRepository struct {
	db *gorm.DB
}

func NewRegionSlangRepository(db *gorm.DB) *RegionSlangRepository {
	return &RegionSlangRepository{db: db}
}

func (r *RegionSlangRepository) Create(ctx context.Context, s models.RegionSlang) error {
	slang := gormMappers.RegionSlangToGorm(s)
	if err := r.db.WithContext(ctx).Create(&slang).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionSlangRepository) GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionSlang, error) {
	var sg []gormModels.RegionSlang
	if err := r.db.WithContext(ctx).Preload("Translations").Where("region_id = ?", regionID).Find(&sg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	if len(sg) == 0 {
		return []models.RegionSlang{}, nil
	}
	sl := gormMappers.GormRegionSlangsToDomain(sg)
	return sl, nil
}

func (r *RegionSlangRepository) GetByID(ctx context.Context, id uint) (*models.RegionSlang, error) {
	var sg gormModels.RegionSlang
	if err := r.db.WithContext(ctx).Preload("Translations").First(&sg, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	sl := gormMappers.GormRegionSlangToDomain(sg)
	return &sl, nil
}

func (r *RegionSlangRepository) Update(ctx context.Context, s models.RegionSlang) error {
	sg := gormMappers.RegionSlangToGorm(s)
	if err := r.db.WithContext(ctx).Session(&gorm.Session{FullSaveAssociations: true}).Where("id = ?", s.ID).Updates(&sg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionSlangRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&gormModels.RegionSlang{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
