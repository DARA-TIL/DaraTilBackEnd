package userAchievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByUserIDUC struct {
	repo repo.UserAchievementRepo
}

func NewGetByUserIDUC(repo repo.UserAchievementRepo) *GetByUserIDUC {
	return &GetByUserIDUC{repo: repo}
}
func (uc *GetByUserIDUC) Execute(ctx context.Context, userID uint) ([]models.UserAchievement, error) {
	return uc.repo.GetByUserID(ctx, userID)
}
