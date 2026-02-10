package user

import (
	models2 "DaraTilBackendV2/internal/application/models"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/config"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
	"golang.org/x/crypto/bcrypt"
)

const (
	refreshCookieKey = "refreshToken"
	DeviceWeb        = "Web"
)

type UserHandler struct {
	CreateUC        *userUC.CreateUserUC
	GetAllUC        *userUC.GetAllUsersUC
	GetByEmailUC    *userUC.GetUserByEmailUC
	GetByIdUC       *userUC.GetUserByIdUC
	LvlUpUC         *userUC.LvlUpUC
	UpdateUC        *userUC.UpdateUserUC
	IssueTokenUC    *jwtTokenUC.IssueTokenUC
	GetByUsernameUC *userUC.GetByUsernameUC
	cfg             *config.Config
}

func NewUserHandler(
	createUC *userUC.CreateUserUC,
	getAllUC *userUC.GetAllUsersUC,
	getByEmailUC *userUC.GetUserByEmailUC,
	getByIdUC *userUC.GetUserByIdUC,
	lvlUpUC *userUC.LvlUpUC,
	updateUC *userUC.UpdateUserUC,
	issueTokenUC *jwtTokenUC.IssueTokenUC,
	getByUsernameUC *userUC.GetByUsernameUC,
	cfg *config.Config,
) *UserHandler {
	return &UserHandler{
		CreateUC:        createUC,
		GetAllUC:        getAllUC,
		GetByEmailUC:    getByEmailUC,
		GetByIdUC:       getByIdUC,
		LvlUpUC:         lvlUpUC,
		UpdateUC:        updateUC,
		IssueTokenUC:    issueTokenUC,
		GetByUsernameUC: getByUsernameUC,
		cfg:             cfg,
	}
}

func (h *UserHandler) Register(c *gin.Context) {
	var body dto.RegisterRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	if body.Role == "admin" {
		body.Role = "user"
	}
	user := models.User{
		Username: body.Username,
		Email:    body.Email,
		Password: body.Password,
		Role:     body.Role,
	}
	userCr, err := h.CreateUC.Execute(c.Request.Context(), user)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	accessToken, err := h.issueTokensAndSetCookie(c, userCr)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}
	userDto := dtoMappers.UserToDto(*userCr)
	response.Success(c, 201, userDto, gin.H{"accessToken": accessToken})
}

func (h *UserHandler) Login(c *gin.Context) {
	var body dto.LoginRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	user, err := h.GetByEmailUC.Execute(c.Request.Context(), body.Email)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		response.Fail(c, http.StatusUnauthorized, "Incorrect password")
		return
	}

	accessToken, err := h.issueTokensAndSetCookie(c, user)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	userDto := dtoMappers.UserToDto(*user)
	response.Success(c, 200, userDto, gin.H{"accessToken": accessToken})
}
func (h *UserHandler) OauthLogin(c *gin.Context, provider string) {
	log.Printf("[OAUTH-LOGIN] Incoming %s login request", provider)

	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	gothic.BeginAuthHandler(c.Writer, c.Request)
}

func (h *UserHandler) OauthCallback(c *gin.Context, provider string) {
	redirectError := func(msg string) {
		redirectURL := fmt.Sprintf("%s/login?oauth=error&error=%s", h.cfg.Server.FrontendUrl, msg)
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
	}

	req := c.Request.WithContext(
		context.WithValue(c.Request.Context(), "provider", provider),
	)
	c.Request = req

	userAuth, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		redirectError("Failed to complete auth for provider")
		return
	}

	if userAuth.Email == "" {
		redirectError(fmt.Sprintf("No email provided by %s", provider))
		return
	}
	user, err := h.GetByEmailUC.Execute(c.Request.Context(), userAuth.Email)
	if errors.Is(err, errs.ErrNotFound) {
		baseUsername := userAuth.NickName
		if baseUsername == "" {
			parts := strings.Split(userAuth.Email, "@")
			if len(parts) > 0 {
				baseUsername = parts[0]
			} else {
				baseUsername = "user"
			}
		}
		username, err := GenerateUniqueUsername(c.Request.Context(), baseUsername, h)
		if err != nil {
			redirectError(fmt.Sprintf("Problems with Username %s", provider))
			return
		}
		user = &models.User{
			Username:     username,
			Email:        userAuth.Email,
			Password:     "",
			Avatar:       userAuth.AvatarURL,
			Role:         "user",
			AuthProvider: provider,
		}

		user, err = h.CreateUC.Execute(c.Request.Context(), *user)
		if err != nil {
			redirectError("Failed to create user")
			return
		}
	} else if err != nil {
		redirectError("Internal server error")
		return
	} else {
		log.Printf("[OAUTH-CALLBACK] Existing user found: id=%d, email=%s, provider=%s",
			user.ID, user.Email, user.AuthProvider)
	}

	if user.AuthProvider != provider {
		redirectError("User already signed in with another provider")
		return
	}

	log.Printf("[OAUTH-CALLBACK] Provider verified for user id=%d: %s", user.ID, provider)

	_, err = h.issueTokensAndSetCookie(c, user)
	if err != nil {
		log.Printf("[OAUTH-CALLBACK] Failed to create tokens for user id=%d: %v", user.ID, err)
		redirectError("Failed to create tokens for user")
		return
	}
	log.Printf("[OAUTH-CALLBACK] Tokens generated successfully for user id=%d", user.ID)

	redirectURL := fmt.Sprintf("%s/login?%s",
		h.cfg.Server.FrontendUrl,
		url.Values{"oauth": []string{provider}}.Encode(),
	)
	log.Printf("[OAUTH-CALLBACK] Redirecting user id=%d to %s", user.ID, redirectURL)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *UserHandler) issueTokensAndSetCookie(c *gin.Context, user *models.User) (string, error) {
	meta := models2.TokenMeta{
		Device:    DeviceWeb,
		IpAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	}
	userClaims := models2.UserClaims{
		UserID:   int(user.ID),
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
	}
	issueRes, err := h.IssueTokenUC.Execute(c.Request.Context(), meta, userClaims)
	if err != nil {
		return "", err
	}
	maxAgeSeconds := int(time.Until(issueRes.RefreshExp).Seconds())
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieKey,
		Value:    issueRes.RefreshToken,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	return issueRes.AccessToken, nil
}
