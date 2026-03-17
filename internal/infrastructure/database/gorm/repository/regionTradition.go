package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionTraditionRepository struct {
	db *gorm.DB
}

func NewRegionTraditionsRepository(db *gorm.DB) *RegionTraditionRepository {
	return &RegionTraditionRepository{db: db}
}

func (r *RegionTraditionRepository) Create(ctx context.Context, tradition models.RegionTraditions) error {
	tg := gormMappers.RegionTraditionToGorm(tradition)
	if err := r.db.WithContext(ctx).Create(&tg).Error; err != nil {
		return err
	}
	return nil
}

func (r *RegionTraditionRepository) Update(ctx context.Context, tradition models.RegionTraditions) error {
	tg := gormMappers.RegionTraditionToGorm(tradition)
	if err := r.db.WithContext(ctx).Session(&gorm.Session{FullSaveAssociations: true}).Where("id = ?", tradition.ID).Updates(&tg).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionTraditionRepository) GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionTraditions, error) {
	var tr []gormModels.RegionTraditions
	if err := r.db.WithContext(ctx).Preload("Translations").Where("region_id = ?", regionID).Find(&tr).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	if len(tr) == 0 {
		return []models.RegionTraditions{}, nil
	}
	t := gormMappers.GormRegionTraditionsToDomain(tr)
	return t, nil
}

func (r *RegionTraditionRepository) GetByID(ctx context.Context, id uint) (*models.RegionTraditions, error) {
	var tr gormModels.RegionTraditions
	if err := r.db.WithContext(ctx).Preload("Translations").First(&tr, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	t := gormMappers.GormRegionTraditionToDomain(tr)
	return &t, nil
}

func (r *RegionTraditionRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&gormModels.RegionTraditions{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
