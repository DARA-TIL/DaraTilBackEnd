package userProfile

import (
	"DaraTilBackendV2/internal/application/usecases/userProfileUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type UserProfileHandler struct {
	CreateUC         *userProfileUC.CreateUC
	GetByUserIDUC    *userProfileUC.GetByUserIDUC
	UpdatePinnedAcUC *userProfileUC.UpdatePinnedAchievementsUC
}

func NewUserProfileHandler(
	createUC *userProfileUC.CreateUC,
	getByUserIDUC *userProfileUC.GetByUserIDUC,
	updatePinnedAchUC *userProfileUC.UpdatePinnedAchievementsUC,
) *UserProfileHandler {
	return &UserProfileHandler{
		CreateUC:         createUC,
		GetByUserIDUC:    getByUserIDUC,
		UpdatePinnedAcUC: updatePinnedAchUC,
	}
}

// Create godoc
// @Summary Create user profile
// @Description Creates a user profile.
// @Tags UserProfile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.CreateUserProfile true "User profile creation payload"
// @Success 201 {string} string "success"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /userProfile/create [post]
func (h *UserProfileHandler) Create(c *gin.Context) {
	var createUP dto.CreateUserProfile
	if err := c.ShouldBindJSON(&createUP); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	cr := dtoMappers.CreateUserProfileToDomain(createUP)
	if err := h.CreateUC.Execute(c.Request.Context(), cr); err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 201, "success")
}

// GetByUserID godoc
// @Summary Get user profile by user ID
// @Description Returns a user profile by user ID.
// @Tags UserProfile
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} dto.UserProfile "User profile"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /userProfile/getByUserId/{id} [get]
func (h *UserProfileHandler) GetByUserID(c *gin.Context) {
	userID, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	up, err := h.GetByUserIDUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	resp := dtoMappers.UserProfileToDTO(*up)
	response.Success(c, 200, resp)
}

// UpdatePinnedAchievements godoc
// @Summary Update pinned achievements
// @Description Updates pinned achievements in the user profile.
// @Tags UserProfile
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.UserProfileUpdate true "Pinned achievements update payload"
// @Success 200 {string} string "success"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /userProfile/updatePinnedAchievements [patch]
func (h *UserProfileHandler) UpdatePinnedAchievements(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	var updateUP dto.UserProfileUpdate
	if err = c.ShouldBindJSON(&updateUP); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	updDom := dtoMappers.UpdatePinnedAchievementsToDomain(updateUP, *userID)
	err = h.UpdatePinnedAcUC.Execute(c.Request.Context(), updDom)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "success")
}
