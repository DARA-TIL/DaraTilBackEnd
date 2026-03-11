package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.RegionTranslationRepo
}

func NewCreateUC(repo repo.RegionTranslationRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, tr models.RegionTranslation) error {
	return uc.repo.Create(ctx, tr)
}
