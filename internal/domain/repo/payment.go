package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type PaymentRepo interface {
	Create(ctx context.Context, payment models.Payment) (*models.Payment, error)
	Update(ctx context.Context, id uint, params models.PatchPaymentParams) (*models.Payment, error)

	GetByID(ctx context.Context, id uint) (*models.Payment, error)
	GetByProviderPaymentID(ctx context.Context, providerPaymentID string) (*models.Payment, error)

	List(ctx context.Context, params models.ListPaymentsParams) ([]models.Payment, error)
}
