package achievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.AchievementRepo
}

func NewGetAllUC(repo repo.AchievementRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}
func (uc *GetAllUC) Execute(ctx context.Context, userID uint) ([]models.Achievement, error) {
	return uc.repo.GetAll(ctx, userID)
}
