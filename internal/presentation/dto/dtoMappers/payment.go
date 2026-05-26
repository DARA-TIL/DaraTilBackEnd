package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func PaymentToResponse(payment models.Payment) dto.PaymentResponse {
	return dto.PaymentResponse{
		ID:                payment.ID,
		UserID:            payment.UserID,
		PlanID:            payment.PlanID,
		Amount:            payment.Amount,
		Currency:          payment.Currency,
		Status:            payment.Status,
		Provider:          payment.Provider,
		ProviderPaymentID: payment.ProviderPaymentID,
		PaymentURL:        payment.PaymentURL,
		PaidAt:            payment.PaidAt,
		CreatedAt:         payment.CreatedAt,
		UpdatedAt:         payment.UpdatedAt,
	}
}
