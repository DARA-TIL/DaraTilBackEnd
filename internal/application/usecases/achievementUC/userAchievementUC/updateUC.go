package userAchievementUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.UserAchievementRepo
}

func NewUpdateUC(repo repo.UserAchievementRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, ua models.UserAchievement) error {
	if ua.UserID != 0 || ua.AchievementID != 0 {
		return errs.ErrBadRequest
	}
	if ua.ID == 0 {
		return errs.ErrBadRequest
	}
	return uc.repo.Update(ctx, ua)
}
