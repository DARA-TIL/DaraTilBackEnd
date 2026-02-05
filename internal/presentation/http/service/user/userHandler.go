package user

import (
	models2 "DaraTilBackendV2/internal/application/models"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	refreshCookieKey = "refreshToken"
	DeviceWeb        = "Web"
)

type UserHandler struct {
	CreateUC     userUC.CreateUserUC
	GetAllUC     userUC.GetAllUsersUC
	GetByEmailUC userUC.GetUserByEmailUC
	GetByIdUC    userUC.GetUserByIdUC
	LvlUpUC      userUC.LvlUpUC
	UpdateUC     userUC.UpdateUserUC
	IssueToken   jwtTokenUC.IssueTokenUC
}

func NewUserHandler(
	createUC userUC.CreateUserUC,
	getAllUC userUC.GetAllUsersUC,
	getByEmailUC userUC.GetUserByEmailUC,
	getByIdUC userUC.GetUserByIdUC,
	lvlUpUC userUC.LvlUpUC,
	updateUC userUC.UpdateUserUC,
	issueTokenUC jwtTokenUC.IssueTokenUC,
) *UserHandler {
	return &UserHandler{
		CreateUC:     createUC,
		GetAllUC:     getAllUC,
		GetByEmailUC: getByEmailUC,
		GetByIdUC:    getByIdUC,
		LvlUpUC:      lvlUpUC,
		UpdateUC:     updateUC,
		IssueToken:   issueTokenUC,
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
	userCr, err := h.CreateUC.Execute(c.Request.Context(), user, "email")
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
	issueRes, err := h.IssueToken.Execute(c.Request.Context(), meta, userClaims)
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
