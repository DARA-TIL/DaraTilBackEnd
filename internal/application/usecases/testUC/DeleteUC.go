package testUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.TestRepo
}

func NewDeleteUC(repo repo.TestRepo) *DeleteUC {
	return &DeleteUC{repo: repo}
}

func (uc *DeleteUC) Execute(ctx context.Context, id uint) error {
	return uc.repo.Delete(ctx, id)
}
