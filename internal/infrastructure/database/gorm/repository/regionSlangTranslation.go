package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionSlangTranslationRepository struct {
	db *gorm.DB
}

func NewRegionSlangTranslationRepository(db *gorm.DB) *RegionSlangTranslationRepository {
	return &RegionSlangTranslationRepository{db: db}
}

func (r *RegionSlangTranslationRepository) Create(ctx context.Context, t models.RegionSlangTranslation) error {
	tg := gormMappers.RegionSlangTranslationToGorm(t)
	if err := r.db.WithContext(ctx).Create(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionSlangTranslationRepository) Update(ctx context.Context, t models.RegionSlangTranslation) error {
	tg := gormMappers.RegionSlangTranslationToGorm(t)
	if err := r.db.WithContext(ctx).Updates(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionSlangTranslationRepository) GetBySlangID(ctx context.Context, regionSlangID uint) ([]models.RegionSlangTranslation, error) {
	var trg []gormModels.RegionSlangTranslation
	if err := r.db.WithContext(ctx).Where("region_slang_id = ? = ?", regionSlangID).Find(&trg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	tr := gormMappers.GormRegionSlangTranslationsToDomain(trg)
	return tr, nil
}

func (r *RegionSlangTranslationRepository) GetByID(ctx context.Context, id uint) (*models.RegionSlangTranslation, error) {
	var trg gormModels.RegionSlangTranslation
	if err := r.db.WithContext(ctx).First(&trg, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	tr := gormMappers.GormRegionSlangTranslationToDomain(trg)
	return &tr, nil
}

func (r *RegionSlangTranslationRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&gormModels.RegionSlangTranslation{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
