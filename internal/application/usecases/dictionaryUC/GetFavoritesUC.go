package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFavoritesUC struct {
	repo repo.DictionaryRepo
}

func NewGetFavoritesUC(repo repo.DictionaryRepo) *GetFavoritesUC {
	return &GetFavoritesUC{repo: repo}
}
func (uc *GetFavoritesUC) Execute(ctx context.Context, userID uint) ([]models.Word, error) {
	return uc.repo.GetFavorites(ctx, userID)
}
