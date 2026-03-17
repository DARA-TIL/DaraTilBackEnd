package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type RegionRepo interface {
	Create(ctx context.Context, region models.Region) error
	Update(ctx context.Context, region models.Region) error
	GetAll(ctx context.Context) ([]models.Region, error)
	GetByID(ctx context.Context, id uint) (*models.Region, error)
	Delete(ctx context.Context, id uint) error
	CreateMulti(ctx context.Context, regions []models.Region) error
	GetByCode(ctx context.Context, code string) (*models.Region, error)
}

type RegionTranslationRepo interface {
	Create(ctx context.Context, t models.RegionTranslation) error
	Update(ctx context.Context, t models.RegionTranslation) error
	GetByID(ctx context.Context, id uint) (*models.RegionTranslation, error)
	GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionTranslation, error)
	Delete(ctx context.Context, id uint) error
}
