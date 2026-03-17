package achievementUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.AchievementRepo
}

func NewUpdateUC(repo repo.AchievementRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, a models.Achievement) error {
	if a.ID == 0 {
		return errs.ErrBadRequest
	}
	return uc.repo.Update(ctx, a)
}
