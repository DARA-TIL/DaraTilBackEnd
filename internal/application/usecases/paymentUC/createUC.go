package paymentUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"fmt"
)

type CreatePaymentUC struct {
	paymentRepo repo.PaymentRepo
	planRepo    repo.SubscriptionPlanRepo
	provider    repo.PaymentProviderClient
}

func NewCreatePaymentUC(
	paymentRepo repo.PaymentRepo,
	planRepo repo.SubscriptionPlanRepo,
	provider repo.PaymentProviderClient,
) *CreatePaymentUC {
	return &CreatePaymentUC{
		paymentRepo: paymentRepo,
		planRepo:    planRepo,
		provider:    provider,
	}
}

func (uc *CreatePaymentUC) Execute(
	ctx context.Context,
	userID uint,
	planID uint,
) (*models.Payment, error) {
	if userID == 0 || planID == 0 {
		return nil, errs.ErrInvalidInput
	}

	plan, err := uc.planRepo.GetByID(ctx, planID)
	if err != nil {
		return nil, err
	}

	if !plan.IsActive {
		return nil, errs.ErrInvalidInput
	}

	payment := models.Payment{
		UserID:   userID,
		PlanID:   plan.ID,
		Amount:   plan.Price,
		Currency: "KZT",
		Status:   models.PaymentStatusPending,
		Provider: models.PaymentProviderMock,
	}

	createdPayment, err := uc.paymentRepo.Create(ctx, payment)
	if err != nil {
		return nil, err
	}

	providerPayment, err := uc.provider.CreatePayment(ctx, repo.CreateProviderPaymentRequest{
		PaymentID: createdPayment.ID,
		UserID:    userID,
		PlanID:    plan.ID,
		Amount:    plan.Price,
		Currency:  "KZT",
		Description: fmt.Sprintf(
			"Subscription plan: %s",
			plan.Name,
		),
	})
	if err != nil {
		return nil, err
	}

	status := models.PaymentStatusPending

	updatedPayment, err := uc.paymentRepo.Update(ctx, createdPayment.ID, models.PatchPaymentParams{
		Status:            &status,
		ProviderPaymentID: &providerPayment.ProviderPaymentID,
		PaymentURL:        &providerPayment.PaymentURL,
	})
	if err != nil {
		return nil, err
	}

	return updatedPayment, nil
}
