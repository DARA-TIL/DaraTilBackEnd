package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type CreateSubscriptionRequest struct {
	UserID      uint       `json:"userId" binding:"required"`
	PlanID      uint       `json:"planId" binding:"required"`
	ActiveUntil *time.Time `json:"activeUntil"`
}

type UpdateSubscriptionRequest struct {
	Status      *models.SubscriptionStatus `json:"status,omitempty"`
	PlanID      *uint                      `json:"planId,omitempty"`
	ActiveUntil *time.Time                 `json:"activeUntil,omitempty"`
	CancelledAt *time.Time                 `json:"cancelledAt,omitempty"`
}

type SubscriptionResponse struct {
	ID uint `json:"id"`

	UserID uint `json:"userId"`

	Status models.SubscriptionStatus `json:"status"`

	PlanID uint                     `json:"planId"`
	Plan   SubscriptionPlanResponse `json:"plan"`

	ActiveUntil time.Time  `json:"activeUntil"`
	CancelledAt *time.Time `json:"cancelledAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SubscriptionShortResponse struct {
	ID uint `json:"id"`

	UserID uint `json:"userId"`

	Status models.SubscriptionStatus `json:"status"`

	PlanID uint `json:"planId"`

	ActiveUntil time.Time  `json:"activeUntil"`
	CancelledAt *time.Time `json:"cancelledAt,omitempty"`
}

type ListSubscriptionsRequest struct {
	UserID *uint                      `form:"userId"`
	PlanID *uint                      `form:"planId"`
	Status *models.SubscriptionStatus `form:"status"`

	Limit  int `form:"limit"`
	Offset int `form:"offset"`
}

type CreateSubscriptionPlanRequest struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description,omitempty"`

	Price        int `json:"price" binding:"required"`
	DurationDays int `json:"durationDays" binding:"required"`

	IsActive bool `json:"isActive"`
}

type UpdateSubscriptionPlanRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`

	Price        *int `json:"price,omitempty"`
	DurationDays *int `json:"durationDays,omitempty"`

	IsActive *bool `json:"isActive,omitempty"`
}

type SubscriptionPlanResponse struct {
	ID uint `json:"id"`

	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`

	Price        int `json:"price"`
	DurationDays int `json:"durationDays"`

	IsActive bool `json:"isActive"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SubscriptionPlanShortResponse struct {
	ID uint `json:"id"`

	Name string `json:"name"`

	Price        int `json:"price"`
	DurationDays int `json:"durationDays"`

	IsActive bool `json:"isActive"`
}

type ListSubscriptionPlansRequest struct {
	Search       *string `form:"search"`
	DurationDays *int    `form:"durationDays"`
	IsActive     *bool   `form:"isActive"`
}
