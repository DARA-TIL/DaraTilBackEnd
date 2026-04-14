package userProfileUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdatePinnedAchievementsUC struct {
	repo repo.UserProfileRepo
}

func NewUpdatePinnedAchievementsUC(repo repo.UserProfileRepo) *UpdatePinnedAchievementsUC {
	return &UpdatePinnedAchievementsUC{repo: repo}
}

func (uc *UpdatePinnedAchievementsUC) Execute(ctx context.Context, up models.UserProfileUpdate) error {
	return uc.repo.UpdatePinnedAchievements(ctx, up)
}
