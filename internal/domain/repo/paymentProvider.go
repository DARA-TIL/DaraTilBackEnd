package repo

import (
	"context"
)

type CreateProviderPaymentRequest struct {
	PaymentID uint
	UserID    uint
	PlanID    uint

	Amount   int
	Currency string

	Description string
}

type CreateProviderPaymentResponse struct {
	ProviderPaymentID string
	PaymentURL        string
}

type PaymentProviderClient interface {
	CreatePayment(
		ctx context.Context,
		req CreateProviderPaymentRequest,
	) (*CreateProviderPaymentResponse, error)

	VerifyPayment(
		ctx context.Context,
		providerPaymentID string,
	) (bool, error)
}
