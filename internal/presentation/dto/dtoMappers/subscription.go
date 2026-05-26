package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func CreateSubscriptionRequestToDomainModel(req dto.CreateSubscriptionRequest) models.Subscription {
	return models.Subscription{
		UserID: req.UserID,
		PlanID: req.PlanID,
		Status: models.SubscriptionStatusActive,
	}
}

func UpdateSubscriptionRequestToPatchParams(req dto.UpdateSubscriptionRequest) models.PatchSubscriptionParams {
	return models.PatchSubscriptionParams{
		Status:      req.Status,
		PlanID:      req.PlanID,
		ActiveUntil: req.ActiveUntil,
		CancelledAt: req.CancelledAt,
	}
}

func ListSubscriptionsRequestToParams(req dto.ListSubscriptionsRequest) models.ListSubscriptionsParams {
	return models.ListSubscriptionsParams{
		UserID: req.UserID,
		PlanID: req.PlanID,
		Status: req.Status,
		Limit:  req.Limit,
		Offset: req.Offset,
	}
}

func SubscriptionToResponse(subscription models.Subscription) dto.SubscriptionResponse {
	return dto.SubscriptionResponse{
		ID:          subscription.ID,
		UserID:      subscription.UserID,
		Status:      subscription.Status,
		PlanID:      subscription.PlanID,
		Plan:        SubscriptionPlanToResponse(subscription.Plan),
		ActiveUntil: subscription.ActiveUntil,
		CancelledAt: subscription.CancelledAt,
		CreatedAt:   subscription.CreatedAt,
		UpdatedAt:   subscription.UpdatedAt,
	}
}

func SubscriptionToShortResponse(subscription models.Subscription) dto.SubscriptionShortResponse {
	return dto.SubscriptionShortResponse{
		ID:          subscription.ID,
		UserID:      subscription.UserID,
		Status:      subscription.Status,
		PlanID:      subscription.PlanID,
		ActiveUntil: subscription.ActiveUntil,
		CancelledAt: subscription.CancelledAt,
	}
}

func SubscriptionsToResponse(subscriptions []models.Subscription) []dto.SubscriptionResponse {
	if subscriptions == nil {
		return []dto.SubscriptionResponse{}
	}

	result := make([]dto.SubscriptionResponse, 0, len(subscriptions))

	for _, subscription := range subscriptions {
		result = append(result, SubscriptionToResponse(subscription))
	}

	return result
}

func SubscriptionsToShortResponse(subscriptions []models.Subscription) []dto.SubscriptionShortResponse {
	if subscriptions == nil {
		return []dto.SubscriptionShortResponse{}
	}

	result := make([]dto.SubscriptionShortResponse, 0, len(subscriptions))

	for _, subscription := range subscriptions {
		result = append(result, SubscriptionToShortResponse(subscription))
	}

	return result
}

func CreateSubscriptionPlanRequestToDomainModel(req dto.CreateSubscriptionPlanRequest) models.SubscriptionPlan {
	return models.SubscriptionPlan{
		Name:         req.Name,
		Description:  req.Description,
		Price:        req.Price,
		DurationDays: req.DurationDays,
		IsActive:     req.IsActive,
	}
}

func UpdateSubscriptionPlanRequestToPatchParams(req dto.UpdateSubscriptionPlanRequest) models.PatchSubscriptionPlanParams {
	return models.PatchSubscriptionPlanParams{
		Name:         req.Name,
		Description:  req.Description,
		Price:        req.Price,
		DurationDays: req.DurationDays,
		IsActive:     req.IsActive,
	}
}

func ListSubscriptionPlansRequestToParams(req dto.ListSubscriptionPlansRequest) models.ListSubscriptionPlansParams {
	return models.ListSubscriptionPlansParams{
		Search:       req.Search,
		DurationDays: req.DurationDays,
		IsActive:     req.IsActive,
	}
}

func SubscriptionPlanToResponse(plan models.SubscriptionPlan) dto.SubscriptionPlanResponse {
	return dto.SubscriptionPlanResponse{
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

func SubscriptionPlanToShortResponse(plan models.SubscriptionPlan) dto.SubscriptionPlanShortResponse {
	return dto.SubscriptionPlanShortResponse{
		ID:           plan.ID,
		Name:         plan.Name,
		Price:        plan.Price,
		DurationDays: plan.DurationDays,
		IsActive:     plan.IsActive,
	}
}

func SubscriptionPlansToResponse(plans []models.SubscriptionPlan) []dto.SubscriptionPlanResponse {
	if plans == nil {
		return []dto.SubscriptionPlanResponse{}
	}

	result := make([]dto.SubscriptionPlanResponse, 0, len(plans))

	for _, plan := range plans {
		result = append(result, SubscriptionPlanToResponse(plan))
	}

	return result
}

func SubscriptionPlansToShortResponse(plans []models.SubscriptionPlan) []dto.SubscriptionPlanShortResponse {
	if plans == nil {
		return []dto.SubscriptionPlanShortResponse{}
	}

	result := make([]dto.SubscriptionPlanShortResponse, 0, len(plans))

	for _, plan := range plans {
		result = append(result, SubscriptionPlanToShortResponse(plan))
	}

	return result
}
func DomainSubscriptionPtrToDTO(subscription *models.Subscription) *dto.SubscriptionResponse {
	if subscription == nil {
		return nil
	}

	result := SubscriptionToResponse(*subscription)
	return &result
}
