package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type ToggleLikeUC struct {
	repo repo.FolkloreRepo
}

func NewToggleLikeUC(repo repo.FolkloreRepo) *ToggleLikeUC {
	return &ToggleLikeUC{repo: repo}
}

func (uc *ToggleLikeUC) Execute(ctx context.Context, folkloreID, userID int) (*models.Folklore, bool, error) {
	return uc.repo.ToggleLike(ctx, folkloreID, userID)
}
