package userActivity

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserActivityHandler struct {
	userActivityService *services.UserActivityService
}

func NewUserActivityHandler(userActivityService *services.UserActivityService) *UserActivityHandler {
	return &UserActivityHandler{userActivityService: userActivityService}
}

// GetUserActivities godoc
// @Summary Get User Activities
// @Description Retries recent user activities: Lesson Finish, Folklore like etc. For now there is only three activities:"lesson_completed", "folklore_liked", "folklore_disliked"
// @Tags Activity
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.UserActivityDTO
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /activity [get]
func (h *UserActivityHandler) GetUserActivities(c *gin.Context) {
	id, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	activities, err := h.userActivityService.GetUserActivities(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	dtoAct := dtoMappers.UserActivitiesToDTO(activities)
	response.Success(c, http.StatusOK, dtoAct)
}
