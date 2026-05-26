package subscription

import (
	"DaraTilBackendV2/internal/application/usecases/subscriptionUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type SubscriptionHandler struct {
	createUC            *subscriptionUC.CreateSubscriptionUC
	updateUC            *subscriptionUC.UpdateSubscriptionUC
	deleteUC            *subscriptionUC.DeleteSubscriptionUC
	getByIDUC           *subscriptionUC.GetSubscriptionByIDUC
	getActiveByUserIDUC *subscriptionUC.GetActiveSubscriptionByUserIDUC
	listUC              *subscriptionUC.ListSubscriptionsUC
	cancelUC            *subscriptionUC.CancelSubscriptionUC
	expireUC            *subscriptionUC.ExpireSubscriptionUC
}

func NewSubscriptionHandler(
	createUC *subscriptionUC.CreateSubscriptionUC,
	updateUC *subscriptionUC.UpdateSubscriptionUC,
	deleteUC *subscriptionUC.DeleteSubscriptionUC,
	getByIDUC *subscriptionUC.GetSubscriptionByIDUC,
	getActiveByUserIDUC *subscriptionUC.GetActiveSubscriptionByUserIDUC,
	listUC *subscriptionUC.ListSubscriptionsUC,
	cancelUC *subscriptionUC.CancelSubscriptionUC,
	expireUC *subscriptionUC.ExpireSubscriptionUC,
) *SubscriptionHandler {
	return &SubscriptionHandler{
		createUC:            createUC,
		updateUC:            updateUC,
		deleteUC:            deleteUC,
		getByIDUC:           getByIDUC,
		getActiveByUserIDUC: getActiveByUserIDUC,
		listUC:              listUC,
		cancelUC:            cancelUC,
		expireUC:            expireUC,
	}
}

// Create godoc
// @Summary Create subscription
// @Description Create a new user subscription
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param subscriptionReq body dto.CreateSubscriptionRequest true "Subscription create request"
// @Success 201 {object} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /subscriptions [post]
func (h *SubscriptionHandler) Create(c *gin.Context) {
	var req dto.CreateSubscriptionRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscription, err := h.createUC.Execute(
		c.Request.Context(),
		dtoMappers.CreateSubscriptionRequestToDomainModel(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 201, dtoMappers.SubscriptionToResponse(*subscription))
}

// Update godoc
// @Summary Update subscription
// @Description Update subscription by ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription ID"
// @Param subscriptionReq body dto.UpdateSubscriptionRequest true "Subscription update request"
// @Success 200 {object} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/{id} [patch]
func (h *SubscriptionHandler) Update(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	var req dto.UpdateSubscriptionRequest
	err = c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscription, err := h.updateUC.Execute(
		c.Request.Context(),
		*id,
		dtoMappers.UpdateSubscriptionRequestToPatchParams(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionToResponse(*subscription))
}

// Delete godoc
// @Summary Delete subscription
// @Description Delete subscription by ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription ID"
// @Success 204 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/{id} [delete]
func (h *SubscriptionHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	err = h.deleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 204, "deleted successfully")
}

// GetByID godoc
// @Summary Get subscription by ID
// @Description Get subscription by ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription ID"
// @Success 200 {object} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/{id} [get]
func (h *SubscriptionHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscription, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionToResponse(*subscription))
}

// GetActiveByUserID godoc
// @Summary Get active subscription by user ID
// @Description Get active subscription of user by user ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/users/{id}/active [get]
func (h *SubscriptionHandler) GetActiveByUserID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscription, err := h.getActiveByUserIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionToResponse(*subscription))
}

// List godoc
// @Summary List subscriptions
// @Description Get subscriptions with filters
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userId query int false "User ID"
// @Param planId query int false "Plan ID"
// @Param status query string false "Subscription status"
// @Param limit query int false "Limit"
// @Param offset query int false "Offset"
// @Success 200 {array} dto.SubscriptionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /subscriptions [get]
func (h *SubscriptionHandler) List(c *gin.Context) {
	var req dto.ListSubscriptionsRequest

	err := c.ShouldBindQuery(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	subscriptions, err := h.listUC.Execute(
		c.Request.Context(),
		dtoMappers.ListSubscriptionsRequestToParams(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionsToResponse(subscriptions))
}

// Cancel godoc
// @Summary Cancel subscription
// @Description Cancel subscription by ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription ID"
// @Success 200 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/{id}/cancel [patch]
func (h *SubscriptionHandler) Cancel(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	err = h.cancelUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, "cancelled successfully")
}

// Expire godoc
// @Summary Expire subscription
// @Description Mark subscription as expired by ID
// @Tags Subscriptions
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription ID"
// @Success 200 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscriptions/{id}/expire [patch]
func (h *SubscriptionHandler) Expire(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	err = h.expireUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, "expired successfully")
}
