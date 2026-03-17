package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionTraditionTranslationRepository struct {
	db *gorm.DB
}

func NewRegionTraditionTranslationRepository(db *gorm.DB) *RegionTraditionTranslationRepository {
	return &RegionTraditionTranslationRepository{db: db}
}

func (r *RegionTraditionTranslationRepository) Create(ctx context.Context, t models.RegionTraditionsTranslation) error {
	tg := gormMappers.RegionTraditionTranslationToGorm(t)
	if err := r.db.WithContext(ctx).Create(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionTraditionTranslationRepository) Update(ctx context.Context, t models.RegionTraditionsTranslation) error {
	tg := gormMappers.RegionTraditionTranslationToGorm(t)

	if err := r.db.WithContext(ctx).Where("id = ?", t.ID).Updates(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionTraditionTranslationRepository) GetByTraditionID(ctx context.Context, regionID uint) ([]models.RegionTraditionsTranslation, error) {
	var tg []gormModels.RegionTraditionsTranslation
	if err := r.db.WithContext(ctx).Where("region_traditions_id = ?", regionID).Find(&tg).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	t := gormMappers.GormRegionTraditionsTranslationsToDomain(tg)
	return t, nil
}

func (r *RegionTraditionTranslationRepository) GetByID(ctx context.Context, id uint) (*models.RegionTraditionsTranslation, error) {
	var tg gormModels.RegionTraditionsTranslation
	if err := r.db.WithContext(ctx).First(&tg, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	t := gormMappers.GormRegionTraditionTranslationToDomain(tg)
	return &t, nil
}

func (r *RegionTraditionTranslationRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&gormModels.RegionTraditionsTranslation{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
