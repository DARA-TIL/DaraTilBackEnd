package jwt

import (
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
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type JwtTokenHandler struct {
	CreateUC   *jwtTokenUC.CreateUC
	FindUC     *jwtTokenUC.FindUC
	RevokeUC   *jwtTokenUC.RevokeJwtUC
	FindByIdUC *userUC.GetByIdUC
	cfg        *config.Config
}

func NewJwtTokenHandler(createUc *jwtTokenUC.CreateUC, findUc *jwtTokenUC.FindUC,
	revokeUc *jwtTokenUC.RevokeJwtUC, findByIdUC *userUC.GetByIdUC, cfg *config.Config) *JwtTokenHandler {
	return &JwtTokenHandler{
		CreateUC:   createUc,
		FindUC:     findUc,
		RevokeUC:   revokeUc,
		FindByIdUC: findByIdUC,
		cfg:        cfg,
	}
}

func (h *JwtTokenHandler) CreateAndStoreToken(c *gin.Context, userClaims dto.UserClaims) (*dto.TokenPair, error) {
	logger.Info("Creating token pair",
		zap.Int("user_id", userClaims.UserID),
		zap.String("ip", c.ClientIP()),
	)

	userClaimsDom := dtoMappers.DtoUserClaimsToDomain(userClaims)
	tokens, err := utils.GenerateTokenPair(userClaimsDom, h.cfg)
	if err != nil {
		logger.Error("Failed to generate token pair",
			zap.Int("user_id", userClaims.UserID),
			zap.Error(err),
		)
		return nil, err
	}

	now := time.Now()
	refreshExp := now.Add(time.Hour * time.Duration(h.cfg.Jwt.JwtRefreshExpiresHours))

	tokenModel := models.Token{
		UserID:           int(userClaims.UserID),
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
			zap.Int("user_id", userClaims.UserID),
			zap.Error(err),
		)
		return nil, err
	}

	logger.Info("Refresh token stored successfully",
		zap.Int("user_id", userClaims.UserID),
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
		zap.Int("user_id", claims.UserID),
	)

	storedToken, err := h.FindUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		logger.Error("Refresh token not found in DB",
			zap.Int("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	if time.Now().After(storedToken.Expires) {
		logger.Warn("Refresh token expired",
			zap.Int("user_id", claims.UserID),
		)
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}

	err = h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		logger.Error("Failed to revoke old refresh token",
			zap.Int("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Old refresh token revoked",
		zap.Int("user_id", claims.UserID),
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
			zap.Int("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("New access token issued",
		zap.Int("user_id", claims.UserID),
	)

	response.Success(c, http.StatusOK, "success", gin.H{
		"user":        userClaims,
		"accessToken": tokens.AccessToken,
	})
}

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
		zap.Int("user_id", claims.UserID),
	)

	if err := h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken)); err != nil {
		logger.Error("Failed to revoke refresh token during logout",
			zap.Int("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	deleteCookie()
	logger.Info("Logout successful",
		zap.Int("user_id", claims.UserID),
	)
	c.Status(http.StatusNoContent)
}

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
			zap.Int("user_id", claims.UserID),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("GetMe successful",
		zap.Int("user_id", claims.UserID),
	)

	c.JSON(http.StatusOK, gin.H{"user": user})
}
