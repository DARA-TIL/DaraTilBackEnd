package achievement

import (
	"DaraTilBackendV2/internal/application/usecases/achievementUC/userAchievementUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type UserAchievementHandler struct {
	CreateUC      *userAchievementUC.CreateUC
	DeleteUC      *userAchievementUC.DeleteUC
	GetByIDUC     *userAchievementUC.GetByIDUC
	GetByUserIDUC *userAchievementUC.GetByUserIDUC
	UpdateUC      *userAchievementUC.UpdateUC
}

func NewUserAchievementHandler(
	createUC *userAchievementUC.CreateUC,
	deleteUC *userAchievementUC.DeleteUC,
	getByIDUC *userAchievementUC.GetByIDUC,
	getByUserIDUC *userAchievementUC.GetByUserIDUC,
	updateUC *userAchievementUC.UpdateUC,
) *UserAchievementHandler {
	return &UserAchievementHandler{
		CreateUC:      createUC,
		DeleteUC:      deleteUC,
		GetByIDUC:     getByIDUC,
		GetByUserIDUC: getByUserIDUC,
		UpdateUC:      updateUC,
	}
}

// Create godoc
// @Summary Create user achievement
// @Description Create new user achievement record (admin only)
// @Tags UserAchievement
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userAchievement body dto.UserAchievement true "User achievement data"
// @Success 201 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /userAchievements/create [post]
func (h *UserAchievementHandler) Create(c *gin.Context) {
	var body dto.UserAchievement
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("[USERACHIEVEMENT] bind json err: ", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ua := dtoMappers.UserAchievementToDomain(body)
	err := h.CreateUC.Execute(c.Request.Context(), ua)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] error while creating userAchievement: ", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 201, "success")
}

// Delete godoc
// @Summary Delete user achievement
// @Description Delete user achievement by ID (admin only)
// @Tags UserAchievement
// @Produce json
// @Security BearerAuth
// @Param id path int true "UserAchievement ID"
// @Success 204 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /userAchievements/delete/{id} [delete]
func (h *UserAchievementHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] invalid id: ", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	err = h.DeleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] error while deleting userAchievement: ", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
}

// GetByID godoc
// @Summary Get user achievement by ID
// @Description Get user achievement by record ID (admin only)
// @Tags UserAchievement
// @Produce json
// @Security BearerAuth
// @Param id path int true "UserAchievement ID"
// @Success 200 {object} dto.UserAchievement
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /userAchievements/getById/{id} [get]
func (h *UserAchievementHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] invalid id: ", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ua, err := h.GetByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] error while getting userAchievement: ", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	uaDto := dtoMappers.UserAchievementToDTO(*ua)
	response.Success(c, 200, uaDto)
}

// GetByUserID godoc
// @Summary Get user achievements by user ID
// @Description Get all user achievement records for a specific user (admin only)
// @Tags UserAchievement
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {array} dto.UserAchievement
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /userAchievements/getByUserId/{id} [get]
func (h *UserAchievementHandler) GetByUserID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] invalid id: ", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ua, err := h.GetByUserIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] error while getting userAchievements: ", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	uaDto := dtoMappers.UserAchievementsToDTO(ua)
	response.Success(c, 200, uaDto)
}

// Update godoc
// @Summary Update user achievement
// @Description Update user achievement record (admin only)
// @Tags UserAchievement
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param userAchievement body dto.UserAchievement true "User achievement data"
// @Success 200 {string} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /userAchievements/update [patch]
func (h *UserAchievementHandler) Update(c *gin.Context) {
	var body dto.UserAchievement
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("[USERACHIEVEMENT] invalid json body: ", zap.Error(err))
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	ua := dtoMappers.UserAchievementToDomain(body)
	err := h.UpdateUC.Execute(c.Request.Context(), ua)
	if err != nil {
		logger.Warn("[USERACHIEVEMENT] error while updating userAchievement: ", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "success")
}
