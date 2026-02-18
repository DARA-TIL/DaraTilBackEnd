package testUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.TestRepo
}

func NewCreateUC(repo repo.TestRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, test models.Test) (*models.Test, error) {
	return uc.repo.Create(ctx, test)
}
