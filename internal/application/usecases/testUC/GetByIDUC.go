package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.TestRepo
}

func NewGetByIDUC(repo repo.TestRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}

func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.Test, error) {
	return uc.repo.GetById(ctx, id)
}
