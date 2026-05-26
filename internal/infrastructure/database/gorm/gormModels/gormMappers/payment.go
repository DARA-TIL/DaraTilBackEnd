package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func PaymentToGormModel(payment models.Payment) gormModels.Payment {
	return gormModels.Payment{
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

func GormPaymentToDomain(payment gormModels.Payment) models.Payment {
	return models.Payment{
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

func GormPaymentsToDomain(payments []gormModels.Payment) []models.Payment {
	result := make([]models.Payment, len(payments))

	for i, payment := range payments {
		result[i] = GormPaymentToDomain(payment)
	}

	return result
}
