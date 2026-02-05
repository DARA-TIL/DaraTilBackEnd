package jwt

import (
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/utils"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type JwtTokenHandler struct {
	CreateUC jwtTokenUC.CreateTokenUC
	FindUC   jwtTokenUC.FindTokenUC
	RevokeUC jwtTokenUC.RevokeJwtUC
	cfg      *config.Config
}

func NewJwtTokenHandler(createUc jwtTokenUC.CreateTokenUC, findUc jwtTokenUC.FindTokenUC,
	revokeUc jwtTokenUC.RevokeJwtUC, cfg *config.Config) *JwtTokenHandler {
	return &JwtTokenHandler{
		CreateUC: createUc,
		FindUC:   findUc,
		RevokeUC: revokeUc,
		cfg:      cfg,
	}
}

func (h *JwtTokenHandler) CreateAndStoreToken(c *gin.Context, userClaims dto.UserClaims) (*dto.TokenPair, error) {
	userClaimsDom := dtoMappers.DtoUserClaimsToDomain(userClaims)
	tokens, err := utils.GenerateTokenPair(userClaimsDom, h.cfg)
	if err != nil {
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
		return nil, err
	}
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
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		var body RefreshRequest
		if bindErr := c.ShouldBindJSON(&body); bindErr != nil || body.RefreshToken == "" {
			response.Fail(c, http.StatusUnauthorized, "Session has been expired")
			return
		}
		refreshToken = body.RefreshToken
	}
	claims := &dto.CustomClaims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return []byte(h.cfg.Jwt.JwtRefreshSecret), nil
	})
	if err != nil || !token.Valid {
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}
	if claims.Subject != "refresh" {
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}
	storedToken, err := h.FindUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	if time.Now().After(storedToken.Expires) {
		response.Fail(c, http.StatusUnauthorized, "Session has been expired")
		return
	}

	err = h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	userClaims := dto.UserClaims{
		UserID:   claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
	}
	tokens, err := h.CreateAndStoreToken(c, userClaims)

	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, http.StatusOK, "success", gin.H{"user": userClaims, "accessToken": tokens.AccessToken})
}

func (h *JwtTokenHandler) Logout(c *gin.Context) {
	deleteCookie := func() {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "refreshToken",
			Value:    "",
			Path:     "/",
			MaxAge:   -1, // удалить
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		})
	}
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil || refreshToken == "" {
		deleteCookie()
		log.Printf("[OAUTH-CALLBACK] No refresh token found in cookie")
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
		log.Printf("[OAUTH-CALLBACK] Invalid refresh token: %v", err)
		deleteCookie()
		c.Status(http.StatusNoContent)
		return
	}
	if err := h.RevokeUC.Execute(c.Request.Context(), claims.UserID, utils.HashToken(refreshToken)); err != nil {
		response.HandleDomainError(c, err)
		return
	}
	deleteCookie()
	c.Status(http.StatusNoContent)
}
