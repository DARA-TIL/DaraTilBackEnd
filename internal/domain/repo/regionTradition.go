package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type RegionTraditionRepo interface {
	Create(ctx context.Context, tradition models.RegionTraditions) error
	Update(ctx context.Context, tradition models.RegionTraditions) error
	GetByRegionID(ctx context.Context, regionID uint) ([]models.RegionTraditions, error)
	GetByID(ctx context.Context, id uint) (*models.RegionTraditions, error)
	Delete(ctx context.Context, id uint) error
}

type RegionTraditionTranslationRepo interface {
	Create(ctx context.Context, t models.RegionTraditionsTranslation) error
	Update(ctx context.Context, t models.RegionTraditionsTranslation) error
	GetByTraditionID(ctx context.Context, traditionID uint) ([]models.RegionTraditionsTranslation, error)
	GetByID(ctx context.Context, id uint) (*models.RegionTraditionsTranslation, error)
	Delete(ctx context.Context, id uint) error
}
