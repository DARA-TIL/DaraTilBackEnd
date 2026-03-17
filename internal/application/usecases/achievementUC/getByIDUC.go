package achievementUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.AchievementRepo
}

func NewGetByIDUC(repo repo.AchievementRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, userID, id uint) (*models.Achievement, error) {
	return uc.repo.GetByID(ctx, userID, id)
}
