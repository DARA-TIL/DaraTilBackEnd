package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteFavoriteUC struct {
	repo repo.DictionaryRepo
}

func NewDeleteFavoriteUC(repo repo.DictionaryRepo) *DeleteFavoriteUC {
	return &DeleteFavoriteUC{repo: repo}
}

func (uc *DeleteFavoriteUC) Execute(ctx context.Context, wordID, userID uint) error {
	return uc.repo.RemoveFromFavorite(ctx, wordID, userID)
}
