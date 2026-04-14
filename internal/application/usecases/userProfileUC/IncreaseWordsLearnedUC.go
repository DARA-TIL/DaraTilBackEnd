package userProfileUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type IncreaseWordsLearnedUC struct {
	repo repo.UserProfileRepo
}

func NewIncreaseWordsLearnedUC(repo repo.UserProfileRepo) *IncreaseWordsLearnedUC {
	return &IncreaseWordsLearnedUC{repo: repo}
}

func (uc *IncreaseWordsLearnedUC) Handle(ctx context.Context, e services.Event) error {
	return uc.repo.IncreaseWordsLearned(ctx, e.UserID)
}
func (uc *IncreaseWordsLearnedUC) Category() models.ActionTrigger {
	return models.StatsImprovement
}
