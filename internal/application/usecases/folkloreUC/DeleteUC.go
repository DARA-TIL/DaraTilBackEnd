package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.FolkloreRepo
}

func NewDeleteUC(repo repo.FolkloreRepo) *DeleteUC {
	return &DeleteUC{
		repo: repo,
	}
}

func (uc *DeleteUC) Execute(ctx context.Context, folkloreID int) error {
	return uc.repo.Delete(ctx, folkloreID)
}
