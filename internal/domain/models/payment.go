package models

import "time"

type PaymentStatus string

const (
	PaymentStatusPending PaymentStatus = "pending"
	PaymentStatusPaid    PaymentStatus = "paid"
	PaymentStatusFailed  PaymentStatus = "failed"
	PaymentStatusExpired PaymentStatus = "expired"
)

type PaymentProvider string

const (
	PaymentProviderMock   PaymentProvider = "mock"
	PaymentProviderKaspi  PaymentProvider = "kaspi"
	PaymentProviderStripe PaymentProvider = "stripe"
)

type Payment struct {
	ID uint

	UserID uint
	PlanID uint

	Amount   int
	Currency string

	Status   PaymentStatus
	Provider PaymentProvider

	ProviderPaymentID *string
	PaymentURL        *string

	PaidAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

type CreatePaymentParams struct {
	UserID uint
	PlanID uint

	Amount   int
	Currency string

	Provider PaymentProvider

	ProviderPaymentID *string
	PaymentURL        *string
}

type PatchPaymentParams struct {
	Status *PaymentStatus

	ProviderPaymentID *string
	PaymentURL        *string

	PaidAt *time.Time
}

type ListPaymentsParams struct {
	UserID   *uint
	PlanID   *uint
	Status   *PaymentStatus
	Provider *PaymentProvider

	Limit  int
	Offset int
}
