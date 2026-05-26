package services

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"errors"
	"time"
)

type SubscriptionService struct {
	subscriptionRepo repo.SubscriptionRepo
	planRepo         repo.SubscriptionPlanRepo
}

func NewSubscriptionService(
	subscriptionRepo repo.SubscriptionRepo,
	planRepo repo.SubscriptionPlanRepo,
) *SubscriptionService {
	return &SubscriptionService{
		subscriptionRepo: subscriptionRepo,
		planRepo:         planRepo,
	}
}

func (s *SubscriptionService) ActivateSubscription(
	ctx context.Context,
	userID uint,
	planID uint,
) (*models.Subscription, error) {
	if userID == 0 || planID == 0 {
		return nil, errs.ErrInvalidInput
	}

	plan, err := s.planRepo.GetByID(ctx, planID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, errs.ErrInvalidInput
	}

	now := time.Now()

	activeUntil := now.AddDate(0, 0, plan.DurationDays)

	currentSubscription, err := s.subscriptionRepo.GetActiveByUserID(ctx, userID)
	if err == nil && currentSubscription != nil {
		return s.extendActiveSubscription(ctx, currentSubscription, plan)
	}

	if err != nil && !errors.Is(err, errs.ErrNotFound) {
		return nil, err
	}

	subscription := models.Subscription{
		UserID:      userID,
		PlanID:      plan.ID,
		Status:      models.SubscriptionStatusActive,
		ActiveUntil: activeUntil,
	}

	return s.subscriptionRepo.Create(ctx, subscription)
}

func (s *SubscriptionService) extendActiveSubscription(
	ctx context.Context,
	subscription *models.Subscription,
	plan *models.SubscriptionPlan,
) (*models.Subscription, error) {
	if subscription == nil || plan == nil {
		return nil, errs.ErrInvalidInput
	}

	now := time.Now()

	baseDate := subscription.ActiveUntil
	if baseDate.Before(now) {
		baseDate = now
	}

	activeUntil := baseDate.AddDate(0, 0, plan.DurationDays)

	status := models.SubscriptionStatusActive

	return s.subscriptionRepo.Update(ctx, subscription.ID, models.PatchSubscriptionParams{
		Status:      &status,
		PlanID:      &plan.ID,
		ActiveUntil: &activeUntil,
		CancelledAt: nil,
	})
}
