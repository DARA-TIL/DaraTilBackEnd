package leaderboard

import (
	"DaraTilBackendV2/internal/application/usecases/leaderboardUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"strconv"

	"github.com/gin-gonic/gin"
)

type LeaderboardHandler struct {
	leaderboardUC *leaderboardUC.LeaderboardUC
}

func NewLeaderboardHandler(leaderboardUC *leaderboardUC.LeaderboardUC) *LeaderboardHandler {
	return &LeaderboardHandler{
		leaderboardUC: leaderboardUC,
	}
}

// Get godoc
// @Summary Get leaderboard
// @Description Get leaderboard by metric. Supported metrics: xp, streak.
// @Tags Leaderboard
// @Produce json
// @Security BearerAuth
// @Param metric path string true "Leaderboard metric" Enums(xp, streak)
// @Param limit path int true "Maximum number of users"
// @Success 200 {array} dto.User
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /leaderboard/{metric}/{limit} [get]
func (h *LeaderboardHandler) Get(c *gin.Context) {
	metric := c.Param("metric")
	if metric == "" {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	lim := c.Param("limit")
	limInt, err := strconv.Atoi(lim)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	var users []models.User
	if metric == "streak" {
		users, err = h.leaderboardUC.GetByStreak(c.Request.Context(), limInt)
	} else if metric == "xp" {
		users, err = h.leaderboardUC.GetByXP(c.Request.Context(), limInt)
	} else {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	usersDTO := dtoMappers.UsersToDto(users)
	response.Success(c, 200, usersDTO)
}

// GetProfile godoc
// @Summary Get profile leaderboard
// @Description Get leaderboard based on user profile metrics. Supported metrics: word.
// @Tags Leaderboard
// @Produce json
// @Security BearerAuth
// @Param metric path string true "Profile leaderboard metric" Enums(word)
// @Param limit path int true "Maximum number of profiles"
// @Success 200 {array} dto.UserProfile
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /leaderboard/profile/{metric}/{limit} [get]
func (h *LeaderboardHandler) GetProfile(c *gin.Context) {
	metric := c.Param("metric")
	if metric == "" {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	lim := c.Param("limit")
	limInt, err := strconv.Atoi(lim)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	var up []models.UserProfile
	if metric == "word" {
		up, err = h.leaderboardUC.GetByWords(c.Request.Context(), limInt)
	} else {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	upDto := dtoMappers.UserProfilesToDTO(up)
	response.Success(c, 200, upDto)
}
