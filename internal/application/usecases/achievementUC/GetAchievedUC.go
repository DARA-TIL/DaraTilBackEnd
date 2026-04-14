package achievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAchievedUC struct {
	repo repo.AchievementRepo
}

func NewGetAchievedUC(repo repo.AchievementRepo) *GetAchievedUC {
	return &GetAchievedUC{repo: repo}
}
func (uc *GetAchievedUC) Execute(ctx context.Context, userID uint) ([]models.Achievement, error) {
	return uc.repo.GetAchieved(ctx, userID)
}
