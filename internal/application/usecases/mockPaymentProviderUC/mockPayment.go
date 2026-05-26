package mockPaymentProviderUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"fmt"
)

type MockPaymentProvider struct{}

func NewMockPaymentProvider() *MockPaymentProvider {
	return &MockPaymentProvider{}
}

func (p *MockPaymentProvider) CreatePayment(
	ctx context.Context,
	req repo.CreateProviderPaymentRequest,
) (*repo.CreateProviderPaymentResponse, error) {
	providerPaymentID := fmt.Sprintf("mock-payment-%d", req.PaymentID)

	paymentURL := fmt.Sprintf(
		"http://localhost:8080/api/payments/%d/mock-pay",
		req.PaymentID,
	)

	return &repo.CreateProviderPaymentResponse{
		ProviderPaymentID: providerPaymentID,
		PaymentURL:        paymentURL,
	}, nil
}

func (p *MockPaymentProvider) VerifyPayment(
	ctx context.Context,
	providerPaymentID string,
) (bool, error) {
	return true, nil
}
