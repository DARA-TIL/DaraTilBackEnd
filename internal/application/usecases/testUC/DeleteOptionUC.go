package testUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteOptionUC struct {
	repo repo.TestRepo
}

func NewDeleteOptionUC(repo repo.TestRepo) *DeleteOptionUC {
	return &DeleteOptionUC{repo: repo}
}

func (uc *DeleteOptionUC) Execute(ctx context.Context, id uint) error {
	return uc.repo.DeleteOption(ctx, id)
}
