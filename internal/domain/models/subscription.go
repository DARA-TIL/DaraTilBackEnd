package models

import "time"

type SubscriptionStatus string

const (
	SubscriptionStatusActive    SubscriptionStatus = "active"
	SubscriptionStatusExpired   SubscriptionStatus = "expired"
	SubscriptionStatusCancelled SubscriptionStatus = "cancelled"
)

type Subscription struct {
	ID          uint
	UserID      uint
	Status      SubscriptionStatus
	PlanID      uint
	Plan        SubscriptionPlan
	ActiveUntil time.Time
	CancelledAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type PatchSubscriptionParams struct {
	Status      *SubscriptionStatus
	PlanID      *uint
	ActiveUntil *time.Time
	CancelledAt *time.Time
}
type ListSubscriptionsParams struct {
	UserID *uint
	PlanID *uint
	Status *SubscriptionStatus

	Limit  int
	Offset int
}
type SubscriptionPlan struct {
	ID uint

	Name        string
	Description *string

	Price        int
	DurationDays int

	IsActive bool

	CreatedAt time.Time
	UpdatedAt time.Time
}
type PatchSubscriptionPlanParams struct {
	Name         *string
	Description  *string
	Price        *int
	DurationDays *int
	IsActive     *bool
}

type ListSubscriptionPlansParams struct {
	Search       *string
	DurationDays *int
	IsActive     *bool
}
