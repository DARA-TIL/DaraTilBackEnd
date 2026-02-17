package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetLikedUC struct {
	repo repo.FolkloreRepo
}

func NewGetLikedFolkloreUC(repo repo.FolkloreRepo) *GetLikedUC {
	return &GetLikedUC{
		repo: repo,
	}
}

func (uc *GetLikedUC) Execute(ctx context.Context, userID int) ([]models.Folklore, error) {
	return uc.repo.GetLikedFolklore(ctx, userID)
}
