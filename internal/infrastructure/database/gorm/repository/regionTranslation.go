package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionTranslationRepository struct {
	db *gorm.DB
}

func NewRegionTranslationRepository(db *gorm.DB) *RegionTranslationRepository {
	return &RegionTranslationRepository{db: db}
}

func (r *RegionTranslationRepository) Create(ctx context.Context, t models.RegionTranslation) error {
	tg := gormMappers.RegionTranslationToGorm(t)

	if err := r.db.WithContext(ctx).Create(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *RegionTranslationRepository) Update(ctx context.Context, t models.RegionTranslation) error {
	tg := gormMappers.RegionTranslationToGorm(t)

	if err := r.db.WithContext(ctx).Where("id = ?", t.ID).Updates(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}

func (r *RegionTranslationRepository) GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionTranslation, error) {
	var tg []gormModels.RegionTranslation

	if err := r.db.WithContext(ctx).
		Where("region_id = ?", regionID).
		Find(&tg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	t := gormMappers.GormRegionTranslationsToDomain(tg)
	return t, nil
}

func (r *RegionTranslationRepository) GetByID(ctx context.Context, id uint) (*models.RegionTranslation, error) {
	var tg gormModels.RegionTranslation

	if err := r.db.WithContext(ctx).First(&tg, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	t := gormMappers.GormRegionTranslationToDomain(tg)
	return &t, nil
}

func (r *RegionTranslationRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).
		Unscoped().
		Delete(&gormModels.RegionTranslation{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}

	return nil
}
