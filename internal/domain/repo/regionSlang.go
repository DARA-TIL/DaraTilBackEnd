package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type RegionSlangRepo interface {
	Create(ctx context.Context, s models.RegionSlang) error
	GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionSlang, error)
	GetByID(ctx context.Context, id uint) (*models.RegionSlang, error)
	Update(ctx context.Context, s models.RegionSlang) error
	Delete(ctx context.Context, id uint) error
}

type RegionSlangTranslationRepo interface {
	Create(ctx context.Context, t models.RegionSlangTranslation) error
	Update(ctx context.Context, t models.RegionSlangTranslation) error
	GetBySlangID(ctx context.Context, regionSlangID uint) ([]models.RegionSlangTranslation, error)
	GetByID(ctx context.Context, id uint) (*models.RegionSlangTranslation, error)
	Delete(ctx context.Context, id uint) error
}
