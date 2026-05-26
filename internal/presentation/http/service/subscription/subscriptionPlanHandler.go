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

type SubscriptionPlanHandler struct {
	createUC  *subscriptionUC.CreateSubscriptionPlanUC
	updateUC  *subscriptionUC.UpdateSubscriptionPlanUC
	deleteUC  *subscriptionUC.DeleteSubscriptionPlanUC
	getByIDUC *subscriptionUC.GetSubscriptionPlanByIDUC
	listUC    *subscriptionUC.ListSubscriptionPlansUC
}

func NewSubscriptionPlanHandler(
	createUC *subscriptionUC.CreateSubscriptionPlanUC,
	updateUC *subscriptionUC.UpdateSubscriptionPlanUC,
	deleteUC *subscriptionUC.DeleteSubscriptionPlanUC,
	getByIDUC *subscriptionUC.GetSubscriptionPlanByIDUC,
	listUC *subscriptionUC.ListSubscriptionPlansUC,
) *SubscriptionPlanHandler {
	return &SubscriptionPlanHandler{
		createUC:  createUC,
		updateUC:  updateUC,
		deleteUC:  deleteUC,
		getByIDUC: getByIDUC,
		listUC:    listUC,
	}
}

// Create godoc
// @Summary Create subscription plan
// @Description Create a new subscription plan
// @Tags Subscription Plans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param planReq body dto.CreateSubscriptionPlanRequest true "Subscription plan create request"
// @Success 201 {object} dto.SubscriptionPlanResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /subscription-plans [post]
func (h *SubscriptionPlanHandler) Create(c *gin.Context) {
	var req dto.CreateSubscriptionPlanRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	plan, err := h.createUC.Execute(
		c.Request.Context(),
		dtoMappers.CreateSubscriptionPlanRequestToDomainModel(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 201, dtoMappers.SubscriptionPlanToResponse(*plan))
}

// Update godoc
// @Summary Update subscription plan
// @Description Update subscription plan by ID
// @Tags Subscription Plans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription plan ID"
// @Param planReq body dto.UpdateSubscriptionPlanRequest true "Subscription plan update request"
// @Success 200 {object} dto.SubscriptionPlanResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscription-plans/{id} [patch]
func (h *SubscriptionPlanHandler) Update(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	var req dto.UpdateSubscriptionPlanRequest
	err = c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	plan, err := h.updateUC.Execute(
		c.Request.Context(),
		*id,
		dtoMappers.UpdateSubscriptionPlanRequestToPatchParams(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionPlanToResponse(*plan))
}

// Delete godoc
// @Summary Delete subscription plan
// @Description Delete subscription plan by ID
// @Tags Subscription Plans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription plan ID"
// @Success 204 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscription-plans/{id} [delete]
func (h *SubscriptionPlanHandler) Delete(c *gin.Context) {
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
// @Summary Get subscription plan by ID
// @Description Get subscription plan by ID
// @Tags Subscription Plans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Subscription plan ID"
// @Success 200 {object} dto.SubscriptionPlanResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /subscription-plans/{id} [get]
func (h *SubscriptionPlanHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	plan, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionPlanToResponse(*plan))
}

// List godoc
// @Summary List subscription plans
// @Description Get subscription plans with filters
// @Tags Subscription Plans
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param search query string false "Search by name"
// @Param durationDays query int false "Duration days"
// @Param isActive query bool false "Is active"
// @Success 200 {array} dto.SubscriptionPlanResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /subscription-plans [get]
func (h *SubscriptionPlanHandler) List(c *gin.Context) {
	var req dto.ListSubscriptionPlansRequest

	err := c.ShouldBindQuery(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	plans, err := h.listUC.Execute(
		c.Request.Context(),
		dtoMappers.ListSubscriptionPlansRequestToParams(req),
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 200, dtoMappers.SubscriptionPlansToResponse(plans))
}
