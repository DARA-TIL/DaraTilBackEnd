package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetBySlangIDUC struct {
	repo repo.RegionSlangTranslationRepo
}

func NewGetBySlangIDUC(repo repo.RegionSlangTranslationRepo) *GetBySlangIDUC {
	return &GetBySlangIDUC{repo: repo}
}

func (uc *GetBySlangIDUC) Execute(ctx context.Context, slangID uint) ([]models.RegionSlangTranslation, error) {
	return uc.repo.GetBySlangID(ctx, slangID)
}
