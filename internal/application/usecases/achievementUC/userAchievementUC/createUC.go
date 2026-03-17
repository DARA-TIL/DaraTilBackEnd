package userAchievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.UserAchievementRepo
}

func NewCreateUC(repo repo.UserAchievementRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, ua models.UserAchievement) error {
	return uc.repo.Create(ctx, ua)
}
