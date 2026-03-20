package actionRule

import (
	"DaraTilBackendV2/internal/application/usecases/actionRuleUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type ActionRuleHandler struct {
	CreateUC      *actionRuleUC.CreateUC
	CreateMultiUC *actionRuleUC.CreateMultiUC
	UpdateUC      *actionRuleUC.UpdateUC
	DeleteUC      *actionRuleUC.DeleteUC
	GetAllUC      *actionRuleUC.GetAllUC
	GetByActionUC *actionRuleUC.GetActionRuleByActionUC
}

func NewActionRuleHandler(
	createUC *actionRuleUC.CreateUC,
	createMultiUC *actionRuleUC.CreateMultiUC,
	updateUC *actionRuleUC.UpdateUC,
	deleteUC *actionRuleUC.DeleteUC,
	getAllUC *actionRuleUC.GetAllUC,
	getByActionUC *actionRuleUC.GetActionRuleByActionUC,
) *ActionRuleHandler {
	return &ActionRuleHandler{
		CreateUC:      createUC,
		CreateMultiUC: createMultiUC,
		UpdateUC:      updateUC,
		DeleteUC:      deleteUC,
		GetAllUC:      getAllUC,
		GetByActionUC: getByActionUC,
	}
}

// Create godoc
// @Summary Create action rule
// @Description Create new action rule (admin only)
// @Tags ActionRule
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.ActionRuleDTO true "ActionRule payload"
// @Success 201 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /actionRules/create [post]
func (h *ActionRuleHandler) Create(c *gin.Context) {
	var body dto.ActionRuleDTO

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Error("[ACTION RULE CREATE] bind error", zap.Error(err))
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	domain := dtoMappers.ActionRuleToDomain(body)

	if err := h.CreateUC.Execute(c.Request.Context(), domain); err != nil {
		logger.Error("[ACTION RULE CREATE] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, "success")
}

// CreateMulti godoc
// @Summary Create multiple action rules
// @Description Create multiple action rules (admin only)
// @Tags ActionRule
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body []dto.ActionRuleDTO true "ActionRules payload"
// @Success 201 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /actionRules/createMulti [post]
func (h *ActionRuleHandler) CreateMulti(c *gin.Context) {
	var body []dto.ActionRuleDTO

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Error("[ACTION RULE CREATE MULTI] bind error", zap.Error(err))
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	domain := dtoMappers.ActionRulesToDomain(body)

	if err := h.CreateMultiUC.Execute(c.Request.Context(), domain); err != nil {
		logger.Error("[ACTION RULE CREATE MULTI] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, "success")
}

// Update godoc
// @Summary Update action rule
// @Description Update action rule (admin only)
// @Tags ActionRule
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.ActionRuleDTO true "ActionRule payload"
// @Success 200 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /actionRules/update [patch]
func (h *ActionRuleHandler) Update(c *gin.Context) {
	var body dto.ActionRuleDTO

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Error("[ACTION RULE UPDATE] bind error", zap.Error(err))
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	domain := dtoMappers.ActionRuleToDomain(body)

	if err := h.UpdateUC.Execute(c.Request.Context(), domain); err != nil {
		logger.Error("[ACTION RULE UPDATE] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "success")
}

// Delete godoc
// @Summary Delete action rule
// @Description Delete action rule by action (admin only)
// @Tags ActionRule
// @Produce json
// @Security BearerAuth
// @Param action path string true "Action"
// @Success 204 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /actionRules/delete/{action} [delete]
func (h *ActionRuleHandler) Delete(c *gin.Context) {
	action := c.Param("action")
	if action == "" {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	if err := h.DeleteUC.Execute(c.Request.Context(), models.Actions(action)); err != nil {
		logger.Error("[ACTION RULE DELETE] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, http.StatusNoContent, "deleted")
}

// GetAll godoc
// @Summary Get all action rules
// @Description Get all action rules (admin only)
// @Tags ActionRule
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.ActionRuleDTO
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /actionRules/getAll [get]
func (h *ActionRuleHandler) GetAll(c *gin.Context) {
	rules, err := h.GetAllUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("[ACTION RULE GET ALL] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	dto := dtoMappers.ActionRulesToDto(rules)

	response.Success(c, http.StatusOK, dto)
}

// GetByAction godoc
// @Summary Get action rule by action
// @Description Get action rule by action (admin only)
// @Tags ActionRule
// @Produce json
// @Security BearerAuth
// @Param action path string true "Action"
// @Success 200 {object} dto.ActionRuleDTO
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /actionRules/get/{action} [get]
func (h *ActionRuleHandler) GetByAction(c *gin.Context) {
	action := c.Param("action")
	if action == "" {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	rule, err := h.GetByActionUC.Execute(
		c.Request.Context(),
		models.Actions(action),
	)
	if err != nil {
		logger.Error("[ACTION RULE GET BY ACTION] error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}

	dto := dtoMappers.ActionRuleToDTO(rule)

	response.Success(c, http.StatusOK, dto)
}
