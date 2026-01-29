package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteFolkloreUC struct {
	Repo repo.FolkloreRepo
}

func NewDeleteFolkloreUC(repo repo.FolkloreRepo) DeleteFolkloreUC {
	return DeleteFolkloreUC{
		Repo: repo,
	}
}

func (uc DeleteFolkloreUC) Execute(ctx context.Context, folkloreID int) error {
	return uc.Repo.Delete(ctx, folkloreID)
}
