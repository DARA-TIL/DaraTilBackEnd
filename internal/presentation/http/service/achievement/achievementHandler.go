package achievement

import (
	"DaraTilBackendV2/internal/application/usecases/achievementUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AchievementHandler struct {
	CreateUC      *achievementUC.CreateUC
	DeleteUC      *achievementUC.DeleteUC
	GetAllUC      *achievementUC.GetAllUC
	GetByIDUC     *achievementUC.GetByIDUC
	UpdateUC      *achievementUC.UpdateUC
	GetAchievedUC *achievementUC.GetAchievedUC
}

func NewAchievementHandler(
	createUC *achievementUC.CreateUC,
	deleteUC *achievementUC.DeleteUC,
	getAllUC *achievementUC.GetAllUC,
	getByIDUC *achievementUC.GetByIDUC,
	updateUC *achievementUC.UpdateUC,
	getAchievedUC *achievementUC.GetAchievedUC,
) *AchievementHandler {
	return &AchievementHandler{
		CreateUC:      createUC,
		DeleteUC:      deleteUC,
		GetAllUC:      getAllUC,
		GetByIDUC:     getByIDUC,
		UpdateUC:      updateUC,
		GetAchievedUC: getAchievedUC,
	}
}

// Create godoc
// @Summary Create achievement
// @Description Create new achievement (admin only)
// @Tags Achievement
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param achievement body dto.Achievement true "Achievement data"
// @Success 201 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /achievement/create [post]
func (h *AchievementHandler) Create(c *gin.Context) {
	var body dto.Achievement
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Error("BindJSON fail", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ach := dtoMappers.AchievementToDomain(body)
	err := h.CreateUC.Execute(c.Request.Context(), ach)
	if err != nil {
		logger.Error("[ACHIEVEMENT] Create failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 201, "success")
}

// Delete godoc
// @Summary Delete achievement
// @Description Delete achievement by ID (admin only)
// @Tags Achievement
// @Produce json
// @Security BearerAuth
// @Param id path int true "Achievement ID"
// @Success 204 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /achievement/delete/{id} [delete]
func (h *AchievementHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	err = h.DeleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[ACHIEVEMENT] Delete failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, http.StatusNoContent, "success")
}

// GetAll godoc
// @Summary Get all achievements
// @Description Get all achievements for current user
// @Tags Achievement
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.Achievement
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /achievement/getAll [get]
func (h *AchievementHandler) GetAll(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	ach, err := h.GetAllUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("[ACHIEVEMENT] GetAll failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	achDto := dtoMappers.AchievementsToDTO(ach)
	response.Success(c, 200, achDto)
}

// GetByID godoc
// @Summary Get achievement by ID
// @Description Get achievement details by ID for current user
// @Tags Achievement
// @Produce json
// @Security BearerAuth
// @Param id path int true "Achievement ID"
// @Success 200 {object} dto.Achievement
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /achievement/getById/{id} [get]
func (h *AchievementHandler) GetByID(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ach, err := h.GetByIDUC.Execute(c.Request.Context(), *userID, *id)
	if err != nil {
		logger.Error("[ACHIEVEMENT] GetAll failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	achDto := dtoMappers.AchievementToDTO(*ach)
	response.Success(c, 200, achDto)
}

// Update godoc
// @Summary Update achievement
// @Description Update achievement (admin only)
// @Tags Achievement
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param achievement body dto.Achievement true "Achievement data"
// @Success 200 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /achievement/update [patch]
func (h *AchievementHandler) Update(c *gin.Context) {
	var body dto.Achievement
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Error("BindJSON fail", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ach := dtoMappers.AchievementToDomain(body)
	err := h.UpdateUC.Execute(c.Request.Context(), ach)
	if err != nil {
		logger.Error("[ACHIEVEMENT] Update failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "success")
}

// GetAchieved godoc
// @Summary Get achieved achievements for user
// @Description Get achieved achievement details for current user
// @Tags Achievement
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.Achievement
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /achievement/achieved [get]
func (h *AchievementHandler) GetAchieved(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	ach, err := h.GetAchievedUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("[ACHIEVEMENT] GetAll failed", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	achDto := dtoMappers.AchievementsToDTO(ach)
	response.Success(c, 200, achDto)
}
