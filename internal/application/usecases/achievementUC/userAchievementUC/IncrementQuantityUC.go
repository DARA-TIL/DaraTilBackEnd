package userAchievementUC

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
)

type IncrementQuantityUC struct {
	repo    repo.UserAchievementRepo
	achRepo repo.AchievementRepo
}

func NewIncrementQuantityUC(repo repo.UserAchievementRepo, achRepo repo.AchievementRepo) *IncrementQuantityUC {
	return &IncrementQuantityUC{
		repo:    repo,
		achRepo: achRepo,
	}
}

func (uc *IncrementQuantityUC) Category() models.ActionTrigger {
	return models.EventAchievement
}

func (uc *IncrementQuantityUC) Handle(ctx context.Context, e services.Event) error {
	_, err := uc.achRepo.GetByAction(ctx, e.Action)
	if errors.Is(err, errs.ErrNotFound) {
		return nil
	}
	err = uc.repo.CreateMissingUserAchievements(ctx, e.UserID, e.Action)
	if err != nil {
		return err
	}
	err = uc.repo.IncrementQuantity(ctx, e.UserID, e.Action)
	if err != nil {
		return err
	}
	return nil
}
