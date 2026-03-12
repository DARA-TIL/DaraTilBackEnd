package regionTraditionTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.RegionTraditionTranslationRepo
}

func NewCreateUC(repo repo.RegionTraditionTranslationRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, tr models.RegionTraditionsTranslation) error {
	return uc.repo.Create(ctx, tr)
}
