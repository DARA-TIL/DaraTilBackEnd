package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type FolkloreRepo interface {
	Create(ctx context.Context, folklore models.Folklore) (*models.Folklore, error)
	GetByID(ctx context.Context, id uint) (*models.Folklore, error)
	GetAll(ctx context.Context) ([]models.Folklore, error)
	Update(ctx context.Context, id uint, fields models.UpdatableFolkloreFields) (*models.Folklore, error)
	Delete(ctx context.Context, id uint) error
	ToggleLike(ctx context.Context, folkloreID, userID uint) (*models.Folklore, bool, error)
	GetByQuery(ctx context.Context, query models.FolkloreFilter) ([]models.Folklore, error)
	GetLikedFolklore(ctx context.Context, userID uint) ([]models.Folklore, error)
}
