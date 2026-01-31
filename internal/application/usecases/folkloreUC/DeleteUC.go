package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteFolkloreUC struct {
	repo repo.FolkloreRepo
}

func NewDeleteFolkloreUC(repo repo.FolkloreRepo) DeleteFolkloreUC {
	return DeleteFolkloreUC{
		repo: repo,
	}
}

func (uc DeleteFolkloreUC) Execute(ctx context.Context, folkloreID int) error {
	return uc.repo.Delete(ctx, folkloreID)
}
