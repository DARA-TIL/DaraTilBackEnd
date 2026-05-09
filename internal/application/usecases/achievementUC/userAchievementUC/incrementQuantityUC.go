package userAchievementUC

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
	"fmt"
)

type IncrementQuantityUC struct {
	repo     repo.UserAchievementRepo
	achRepo  repo.AchievementRepo
	notifSub services.NotificationSubscriber
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
	achievements, err := uc.repo.IncrementQuantity(ctx, e.UserID, e.Action)
	if err != nil {
		return err
	}
	if len(achievements) != 0 {
		for _, achievement := range achievements {
			title := fmt.Sprintf("Achievement unlocked: %s", achievement.Achievement.Name)

			message := fmt.Sprintf(
				"You have unlocked the achievement \"%s\". %s",
				achievement.Achievement.Name,
				achievement.Achievement.Description,
			)

			uc.Notify(ctx, models.Notification{
				Title:    title,
				Message:  message,
				Type:     models.NotificationTypeReward,
				Scope:    models.NotificationScopeUser,
				UserID:   &e.UserID,
				EntityID: &achievement.ID,
				IsActive: true,
			})
		}
	}
	return nil
}

func (uc *IncrementQuantityUC) Notify(ctx context.Context, notif models.Notification) {
	uc.notifSub.Handle(ctx, notif)
}

func (uc *IncrementQuantityUC) AddSubscriber(sub services.NotificationSubscriber) {
	uc.notifSub = sub
}
