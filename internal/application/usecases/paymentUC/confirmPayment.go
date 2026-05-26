package paymentUC

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"time"
)

type ConfirmPaymentUC struct {
	paymentRepo         repo.PaymentRepo
	subscriptionService *services.SubscriptionService
}

func NewConfirmPaymentUC(
	paymentRepo repo.PaymentRepo,
	subscriptionService *services.SubscriptionService,
) *ConfirmPaymentUC {
	return &ConfirmPaymentUC{
		paymentRepo:         paymentRepo,
		subscriptionService: subscriptionService,
	}
}

func (uc *ConfirmPaymentUC) Execute(
	ctx context.Context,
	paymentID uint,
) (*models.Subscription, error) {
	if paymentID == 0 {
		return nil, errs.ErrInvalidInput
	}

	payment, err := uc.paymentRepo.GetByID(ctx, paymentID)
	if err != nil {
		return nil, err
	}

	if payment.Status == models.PaymentStatusPaid {
		return uc.subscriptionService.ActivateSubscription(ctx, payment.UserID, payment.PlanID)
	}

	if payment.Status != models.PaymentStatusPending {
		return nil, errs.ErrInvalidInput
	}

	now := time.Now()
	status := models.PaymentStatusPaid

	_, err = uc.paymentRepo.Update(ctx, payment.ID, models.PatchPaymentParams{
		Status: &status,
		PaidAt: &now,
	})
	if err != nil {
		return nil, err
	}

	return uc.subscriptionService.ActivateSubscription(ctx, payment.UserID, payment.PlanID)
}
