package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.TestRepo
}

func NewUpdateUC(repo repo.TestRepo) *UpdateUC {
	return &UpdateUC{
		repo: repo,
	}
}
func (uc *UpdateUC) Execute(ctx context.Context, upd models.TestUpdate) (*models.Test, error) {
	return uc.repo.Update(ctx, upd)
}
