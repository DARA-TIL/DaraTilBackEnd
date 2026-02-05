package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetLikedFolkloreUC struct {
	repo repo.FolkloreRepo
}

func NewGetLikedFolkloreUC(repo repo.FolkloreRepo) *GetLikedFolkloreUC {
	return &GetLikedFolkloreUC{
		repo: repo,
	}
}

func (uc *GetLikedFolkloreUC) Execute(ctx context.Context, userID int) ([]models.Folklore, error) {
	return uc.repo.GetLikedFolklore(ctx, userID)
}
