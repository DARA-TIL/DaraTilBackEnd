package subscriptionUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"time"
)

const FreeDailyActionLimit = 5

type CheckDailyActionLimitUC struct {
	subscriptionRepo repo.SubscriptionRepo
	usageRepo        repo.DailyActionUsageRepo
}

func NewCheckDailyActionLimitUC(
	subscriptionRepo repo.SubscriptionRepo,
	usageRepo repo.DailyActionUsageRepo,
) *CheckDailyActionLimitUC {
	return &CheckDailyActionLimitUC{
		subscriptionRepo: subscriptionRepo,
		usageRepo:        usageRepo,
	}
}

func (uc *CheckDailyActionLimitUC) Execute(
	ctx context.Context,
	userID uint,
	action string,
) error {
	if userID == 0 || action == "" {
		return errs.ErrInvalidInput
	}

	_, err := uc.subscriptionRepo.GetActiveByUserID(ctx, userID)
	if err == nil {
		return nil
	}

	today := time.Now().Truncate(24 * time.Hour)

	usage, err := uc.usageRepo.GetByUserActionDate(ctx, userID, action, today)
	if err == nil && usage.Count >= FreeDailyActionLimit {
		return errs.ErrLimitWithoutPremium
	}

	err = uc.usageRepo.Increment(ctx, userID, action, today)
	if err != nil {
		return err
	}

	return nil
}
