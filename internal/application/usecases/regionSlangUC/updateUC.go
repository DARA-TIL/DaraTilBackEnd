package regionSlangUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
)

type UpdateUC struct {
	repo repo.RegionSlangRepo
}

func NewUpdateUC(repo repo.RegionSlangRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}
func (uc *UpdateUC) Execute(ctx context.Context, tr models.RegionSlang) error {
	if tr.RegionID != 0 {
		tr.RegionID = 0
	}
	if tr.ID == 0 {
		logger.Error("slang id is empty")
		return errs.ErrInvalidInput
	}
	return uc.repo.Update(ctx, tr)
}
