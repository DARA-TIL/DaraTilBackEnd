package jwt

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type JwtTokenHandler struct {
	CreateUC          *jwtTokenUC.CreateUC
	FindUC            *jwtTokenUC.FindUC
	RevokeUC          *jwtTokenUC.RevokeJwtUC
	FindByIdUC        *userUC.GetByIdUC
	UserStreakService *services.StreakService
	cfg               *config.Config
	NotifSub          services.NotificationSubscriber
}

func NewJwtTokenHandler(createUc *jwtTokenUC.CreateUC, findUc *jwtTokenUC.FindUC,
	revokeUc *jwtTokenUC.RevokeJwtUC, findByIdUC *userUC.GetByIdUC, userStreakService *services.StreakService, cfg *config.Config) *JwtTokenHandler {
	return &JwtTokenHandler{
		CreateUC:          createUc,
		FindUC:            findUc,
		RevokeUC:          revokeUc,
		FindByIdUC:        findByIdUC,
		UserStreakService: userStreakService,
		cfg:               cfg,
	}
}

func (h *JwtTokenHandler) CreateAndStoreToken(c *gin.Context, userClaims dto.UserClaims) (*dto.TokenPair, error) {
	logger.Info("Creating token pair",
		zap.Uint("user_id", userClaims.UserID),
		zap.String("ip", c.ClientIP()),
	)

	userClaimsDom := dtoMappers.DtoUserClaimsToDomain(userClaims)
	tokens, err := utils.GenerateTokenPair(userClaimsDom, h.cfg)
	if err != nil {
		logger.Error("Failed to generate token pair",
			zap.Uint("user_id", userClaims.UserID),
			zap.Error(err),
		)
		return nil, err
	}

	now := time.Now()
	refreshExp := now.Add(time.Hour * time.Duration(h.cfg.Jwt.JwtRefreshExpiresHours))

	tokenModel := models.Token{
		UserID:           userClaims.UserID,
		RefreshTokenHash: utils.HashToken(tokens.RefreshToken),
		Device:           "Web",
		IpAddress:        c.ClientIP(),
		UserAgent:        c.Request.UserAgent(),
		IsRevoked:        false,
		Expires:          refreshExp,
		LastUsed:         now,
	}

	_, err = h.CreateUC.Execute(c.Request.Context(), tokenModel)
	if err != nil {
		logger.Error("Failed to store refresh token in DB",
			zap.Uint("user_id", userClaims.UserID),
			zap.Error(err),
		)
		return nil, err
	}

	logger.Info("Refresh token stored successfully",
		zap.Uint("user_id", userClaims.UserID),
	)

	maxAgeSeconds := int(time.Until(refreshExp).Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refreshToken",
		Value:    tokens.RefreshToken,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	tokensDto := dtoMappers.TokenPairToDto(*tokens)
	return &tokensDto, nil
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// RefreshToken godoc
// @Summary Refresh access token
// @Description Validates refresh token (cookie "refreshToken" or JSON body) and issues a new access token. Also rotates refresh token and sets a new "refreshToken" HttpOnly cookie.
// @Tags Auth
// @Accept json
// @Produce json
// @Param refresh body RefreshRequest false "Refresh token (optional if cookie refreshToken exists)"
// @Success 200 {object} dto.RefreshTokenResponse "Returns user and new accessToken"
// @Failure 401 {object} map[string]interface{} "Session has been expired"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /auth/refresh [get]
func (h *JwtTokenHandler) RefreshToken(c *gin.Context) {
	logger.Info("Refresh token request started")
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		logger.Warn("No refresh token found in cookie")
		var body RefreshRequest
		if bindErr := c.ShouldBindJSON(&body); bindErr != nil || body.RefreshToken == "" {
			logger.Warn("No refresh token provided in body")
			response.Fail(c, http.StatusUnauthorized, "Session has been expired")
			return
		}
		refreshToken = body.RefreshToken
	}

	claims := &dto.CustomClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			logger.Error("Invalid signing method in refresh token")
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.Jwt.JwtRefreshSecret), nil
	})

	if err != nil || !token.Valid {
		logger.Warn("Invalid or expired refresh token")
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}

	if claims.Subject != "refresh" {
		logger.Warn("Invalid token subject",
			zap.String("subject", claims.Subject),
		)
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}

	logger.Info("Refresh token validated",
		zap.Uint("user_id", claims.UserID),
	)

	storedToken, err := h.FindUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		logger.Error("Refresh token not found in DB",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	if time.Now().After(storedToken.Expires) {
		logger.Warn("Refresh token expired",
			zap.Uint("user_id", claims.UserID),
		)
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}

	err = h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		logger.Error("Failed to revoke old refresh token",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Old refresh token revoked",
		zap.Uint("user_id", claims.UserID),
	)

	userClaims := dto.UserClaims{
		UserID:   claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
	}

	tokens, err := h.CreateAndStoreToken(c, userClaims)
	if err != nil {
		logger.Error("Failed to create new token pair",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("New access token issued",
		zap.Uint("user_id", claims.UserID),
	)
	resp := dto.RefreshTokenResponse{
		User:        userClaims,
		AccessToken: tokens.AccessToken,
		Status:      "success",
	}
	response.Success(c, http.StatusOK, resp)
}

// Logout godoc
// @Summary Logout user
// @Description Revokes current refresh token (if present) and clears the "refreshToken" cookie.
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 204 "No Content"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /auth/logout [post]
func (h *JwtTokenHandler) Logout(c *gin.Context) {
	logger.Info("Logout request started")

	deleteCookie := func() {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "refreshToken",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
	}

	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		logger.Warn("No refresh token found during logout")
		deleteCookie()
		c.Status(http.StatusNoContent)
		return
	}

	claims := &dto.CustomClaims{}
	_, err = jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.Jwt.JwtRefreshSecret), nil
	})

	if err != nil || claims.Subject != "refresh" {
		logger.Warn("Invalid refresh token during logout")
		deleteCookie()
		c.Status(http.StatusNoContent)
		return
	}

	logger.Info("Revoking refresh token",
		zap.Uint("user_id", claims.UserID),
	)

	if err := h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken)); err != nil {
		logger.Error("Failed to revoke refresh token during logout",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	deleteCookie()
	h.Notify(c.Request.Context(), models.Notification{
		UserID: &claims.UserID,
		Type:   models.NotifLogOut,
	})
	logger.Info("Logout successful",
		zap.Uint("user_id", claims.UserID),
	)
	c.Status(http.StatusNoContent)
}

// GetMe godoc
// @Summary Get current user
// @Description Get authenticated user profile
// @Tags Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.GetMeResponse  "Returns user"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Router /auth/me [get]
func (h *JwtTokenHandler) GetMe(c *gin.Context) {
	logger.Info("GetMe request started")

	claims, isAuth := middleware.GetUserClaims(c)
	if !isAuth {
		logger.Warn("Unauthorized access to GetMe")
		response.Fail(c, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := h.FindByIdUC.Execute(c.Request.Context(), claims.UserID)
	if err != nil {
		logger.Error("Failed to fetch user in GetMe",
			zap.Uint("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}
	userDto := dtoMappers.UserToDto(*user)
	resp := dto.GetMeResponse{
		User: userDto,
	}
	c.JSON(http.StatusOK, resp)
}

func (h *JwtTokenHandler) Notify(ctx context.Context, notif models.Notification) {
	h.NotifSub.Handle(ctx, notif)
}

func (h *JwtTokenHandler) AddSubscriber(sub services.NotificationSubscriber) {
	h.NotifSub = sub
}
