package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type FolkloreRepo interface {
	Create(ctx context.Context, folklore models.Folklore) (*models.Folklore, error)
	GetByID(ctx context.Context, id int) (*models.Folklore, error)
	GetAll(ctx context.Context) ([]models.Folklore, error)
	Update(ctx context.Context, id int, fields models.UpdatableFolkloreFields) (*models.Folklore, error)
	Delete(ctx context.Context, id int) error
	ToggleLike(ctx context.Context, folkloreID, userID int) (*models.Folklore, bool, error)
	GetByQuery(ctx context.Context, query models.FolkloreFilter) ([]models.Folklore, error)
	GetLikedFolklore(ctx context.Context, userID int) ([]models.Folklore, error)
}
