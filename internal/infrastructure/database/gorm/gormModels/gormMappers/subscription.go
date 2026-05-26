package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func SubscriptionToGormModel(subscription models.Subscription) gormModels.Subscription {
	return gormModels.Subscription{
		ID:          subscription.ID,
		UserID:      subscription.UserID,
		Status:      subscription.Status,
		PlanID:      subscription.PlanID,
		ActiveUntil: subscription.ActiveUntil,
		CancelledAt: subscription.CancelledAt,
		CreatedAt:   subscription.CreatedAt,
		UpdatedAt:   subscription.UpdatedAt,
	}
}

func GormSubscriptionToDomain(subscription gormModels.Subscription) models.Subscription {
	return models.Subscription{
		ID:          subscription.ID,
		UserID:      subscription.UserID,
		Status:      subscription.Status,
		PlanID:      subscription.PlanID,
		Plan:        GormSubscriptionPlanToDomain(subscription.Plan),
		ActiveUntil: subscription.ActiveUntil,
		CancelledAt: subscription.CancelledAt,
		CreatedAt:   subscription.CreatedAt,
		UpdatedAt:   subscription.UpdatedAt,
	}
}

func SubscriptionsToGormModel(subscriptions []models.Subscription) []gormModels.Subscription {
	result := make([]gormModels.Subscription, len(subscriptions))

	for i, subscription := range subscriptions {
		result[i] = SubscriptionToGormModel(subscription)
	}

	return result
}

func GormSubscriptionsToDomain(subscriptions []gormModels.Subscription) []models.Subscription {
	result := make([]models.Subscription, len(subscriptions))

	for i, subscription := range subscriptions {
		result[i] = GormSubscriptionToDomain(subscription)
	}

	return result
}

func SubscriptionPlanToGormModel(plan models.SubscriptionPlan) gormModels.SubscriptionPlan {
	return gormModels.SubscriptionPlan{
		ID:           plan.ID,
		Name:         plan.Name,
		Description:  plan.Description,
		Price:        plan.Price,
		DurationDays: plan.DurationDays,
		IsActive:     plan.IsActive,
		CreatedAt:    plan.CreatedAt,
		UpdatedAt:    plan.UpdatedAt,
	}
}

func GormSubscriptionPlanToDomain(plan gormModels.SubscriptionPlan) models.SubscriptionPlan {
	return models.SubscriptionPlan{
		ID:           plan.ID,
		Name:         plan.Name,
		Description:  plan.Description,
		Price:        plan.Price,
		DurationDays: plan.DurationDays,
		IsActive:     plan.IsActive,
		CreatedAt:    plan.CreatedAt,
		UpdatedAt:    plan.UpdatedAt,
	}
}

func SubscriptionPlansToGormModel(plans []models.SubscriptionPlan) []gormModels.SubscriptionPlan {
	result := make([]gormModels.SubscriptionPlan, len(plans))

	for i, plan := range plans {
		result[i] = SubscriptionPlanToGormModel(plan)
	}

	return result
}

func GormSubscriptionPlansToDomain(plans []gormModels.SubscriptionPlan) []models.SubscriptionPlan {
	result := make([]models.SubscriptionPlan, len(plans))

	for i, plan := range plans {
		result[i] = GormSubscriptionPlanToDomain(plan)
	}

	return result
}
func GormSubscriptionPtrToDomain(subscription *gormModels.Subscription) *models.Subscription {
	if subscription == nil {
		return nil
	}

	result := GormSubscriptionToDomain(*subscription)
	return &result
}
