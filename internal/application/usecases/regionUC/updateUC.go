package regionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
)

type UpdateUC struct {
	repo repo.RegionRepo
}

func NewUpdateUC(repo repo.RegionRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}
func (uc *UpdateUC) Execute(ctx context.Context, region models.Region) error {
	if region.ID == 0 {
		logger.Error("Update object's id field is empty")
		return errs.ErrInvalidInput
	}
	return uc.repo.Update(ctx, region)
}
