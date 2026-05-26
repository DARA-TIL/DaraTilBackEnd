package payment

import (
	"DaraTilBackendV2/internal/application/usecases/paymentUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type PaymentHandler struct {
	createPaymentUC  *paymentUC.CreatePaymentUC
	confirmPaymentUC *paymentUC.ConfirmPaymentUC
}

func NewPaymentHandler(
	createPaymentUC *paymentUC.CreatePaymentUC,
	confirmPaymentUC *paymentUC.ConfirmPaymentUC,
) *PaymentHandler {
	return &PaymentHandler{
		createPaymentUC:  createPaymentUC,
		confirmPaymentUC: confirmPaymentUC,
	}
}

// Create godoc
// @Summary Create payment
// @Description Create a new payment for subscription plan. Returns payment URL for completing payment.
// @Tags Payments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param paymentReq body dto.CreatePaymentRequest true "Payment create request"
// @Success 201 {object} dto.PaymentResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /payments [post]
func (h *PaymentHandler) Create(c *gin.Context) {
	var req dto.CreatePaymentRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	payment, err := h.createPaymentUC.Execute(c.Request.Context(), *userID, req.PlanID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 201, dtoMappers.PaymentToResponse(*payment))
}

// MockPay godoc
// @Summary Mock payment confirmation
// @Description Confirm mock payment by payment ID and activate user subscription. This endpoint is used only for local/testing payment flow.
// @Tags Payments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Payment ID"
// @Success 200 {object} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /payments/{id}/mock-pay [get]
func (h *PaymentHandler) MockPay(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscription, err := h.confirmPaymentUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionToResponse(*subscription))
}
