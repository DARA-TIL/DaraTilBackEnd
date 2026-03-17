package achievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.AchievementRepo
}

func NewCreateUC(repo repo.AchievementRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, ua models.Achievement) error {
	return uc.repo.Create(ctx, ua)
}
