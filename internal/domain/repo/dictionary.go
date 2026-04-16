package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type DictionaryRepo interface {
	Create(ctx context.Context, w models.Word) error
	Update(ctx context.Context, w models.Word) error
	Delete(ctx context.Context, id uint) error
	GetAll(ctx context.Context) ([]models.Word, error)
	GetExactWord(ctx context.Context, word string, block string) (*models.Word, error)
	GetWord(ctx context.Context, word string) ([]models.Word, error)
	GetByID(ctx context.Context, id uint) (*models.Word, error)
}
