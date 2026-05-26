package repository

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type PaymentRepository struct {
	db *gorm.DB
}

func NewPaymentRepository(db *gorm.DB) *PaymentRepository {
	return &PaymentRepository{db: db}
}

func (r *PaymentRepository) Create(ctx context.Context, payment models.Payment) (*models.Payment, error) {
	gormPayment := gormMappers.PaymentToGormModel(payment)

	err := r.db.WithContext(ctx).Create(&gormPayment).Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormPaymentToDomain(gormPayment)
	return &result, nil
}

func (r *PaymentRepository) Update(
	ctx context.Context,
	id uint,
	params models.PatchPaymentParams,
) (*models.Payment, error) {
	updates := make(map[string]interface{})

	if params.Status != nil {
		updates["status"] = *params.Status
	}

	if params.ProviderPaymentID != nil {
		updates["provider_payment_id"] = *params.ProviderPaymentID
	}

	if params.PaymentURL != nil {
		updates["payment_url"] = *params.PaymentURL
	}

	if params.PaidAt != nil {
		updates["paid_at"] = *params.PaidAt
	}

	err := r.db.WithContext(ctx).
		Model(&gormModels.Payment{}).
		Where("id = ?", id).
		Updates(updates).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	var gormPayment gormModels.Payment
	err = r.db.WithContext(ctx).
		First(&gormPayment, id).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormPaymentToDomain(gormPayment)
	return &result, nil
}

func (r *PaymentRepository) GetByID(ctx context.Context, id uint) (*models.Payment, error) {
	var gormPayment gormModels.Payment

	err := r.db.WithContext(ctx).
		First(&gormPayment, id).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormPaymentToDomain(gormPayment)
	return &result, nil
}

func (r *PaymentRepository) GetByProviderPaymentID(
	ctx context.Context,
	providerPaymentID string,
) (*models.Payment, error) {
	var gormPayment gormModels.Payment

	err := r.db.WithContext(ctx).
		Where("provider_payment_id = ?", providerPaymentID).
		First(&gormPayment).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	result := gormMappers.GormPaymentToDomain(gormPayment)
	return &result, nil
}

func (r *PaymentRepository) List(
	ctx context.Context,
	params models.ListPaymentsParams,
) ([]models.Payment, error) {
	gormPayments := make([]gormModels.Payment, 0)

	query := r.db.WithContext(ctx).Model(&gormModels.Payment{})

	if params.UserID != nil {
		query = query.Where("user_id = ?", *params.UserID)
	}

	if params.PlanID != nil {
		query = query.Where("plan_id = ?", *params.PlanID)
	}

	if params.Status != nil {
		query = query.Where("status = ?", *params.Status)
	}

	if params.Provider != nil {
		query = query.Where("provider = ?", *params.Provider)
	}

	if params.Limit > 0 {
		query = query.Limit(params.Limit)
	}

	if params.Offset > 0 {
		query = query.Offset(params.Offset)
	}

	err := query.
		Order("created_at DESC").
		Find(&gormPayments).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	if len(gormPayments) == 0 {
		return []models.Payment{}, nil
	}

	result := gormMappers.GormPaymentsToDomain(gormPayments)
	return result, nil
}
