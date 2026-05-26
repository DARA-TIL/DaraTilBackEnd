package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type CreatePaymentRequest struct {
	PlanID uint `json:"planId" binding:"required"`
}

type PaymentResponse struct {
	ID uint `json:"id"`

	UserID uint `json:"userId"`
	PlanID uint `json:"planId"`

	Amount   int    `json:"amount"`
	Currency string `json:"currency"`

	Status   models.PaymentStatus   `json:"status"`
	Provider models.PaymentProvider `json:"provider"`

	ProviderPaymentID *string `json:"providerPaymentId,omitempty"`
	PaymentURL        *string `json:"paymentUrl,omitempty"`

	PaidAt *time.Time `json:"paidAt,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
