package userAchievementUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type IncrementQuantityUC struct {
	repo repo.UserAchievementRepo
}

func NewIncrementQuantityUC(repo repo.UserAchievementRepo) *IncrementQuantityUC {
	return &IncrementQuantityUC{repo: repo}
}

func (uc *IncrementQuantityUC) Execute(ctx context.Context, userID, achievementID uint) error {
	ua, err := uc.repo.GetByUserAndAchieveID(ctx, userID, achievementID)
	if err != nil {
		return err
	}
	if ua.Achieved {
		return nil
	}
	err = uc.repo.IncrementQuantity(ctx, userID, achievementID)
	return err
}
func (uc *IncrementQuantityUC) Handle(ctx context.Context, event services.Event) error {

}
