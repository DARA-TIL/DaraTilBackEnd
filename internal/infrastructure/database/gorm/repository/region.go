package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type RegionRepository struct {
	db *gorm.DB
}

func NewRegionRepository(db *gorm.DB) *RegionRepository {
	return &RegionRepository{db: db}
}

func (r *RegionRepository) Create(ctx context.Context, region models.Region) error {
	gormRegion := gormMappers.RegionToGormModel(region)
	if err := r.db.WithContext(ctx).Create(&gormRegion).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionRepository) Update(ctx context.Context, region models.Region) error {
	gormRegion := gormMappers.RegionToGormModel(region)

	if err := r.db.WithContext(ctx).
		Session(&gorm.Session{FullSaveAssociations: true}).
		Updates(&gormRegion).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}

func (r *RegionRepository) GetAll(ctx context.Context) ([]models.Region, error) {
	var gormRegions []gormModels.Region
	if err := r.db.WithContext(ctx).
		Preload("Translations").
		Preload("RegionSlang.Translations").
		Preload("RegionTraditions.Translations").Order("required_level ASC").Find(&gormRegions).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	regions := make([]models.Region, 0, len(gormRegions))
	for _, region := range gormRegions {
		regions = append(regions, gormMappers.GormRegionToDomain(region))
	}
	return regions, nil
}

func (r *RegionRepository) GetByID(ctx context.Context, id uint) (*models.Region, error) {
	var gormRegion gormModels.Region
	if err := r.db.WithContext(ctx).
		Preload("Translations").
		Preload("RegionSlang.Translations").
		Preload("RegionTraditions.Translations").First(&gormRegion, id).Error; err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}
	region := gormMappers.GormRegionToDomain(gormRegion)
	return &region, nil
}

func (r *RegionRepository) Delete(ctx context.Context, id uint) error {
	if err := r.db.WithContext(ctx).Unscoped().Delete(&gormModels.Region{}, id).Error; err != nil {
		return errhandlers.DBErrHandler(err)
	}
	return nil
}
