package user

import (
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/application/usecases/jwtTokenUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	"DaraTilBackendV2/internal/config"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type UserHandler struct {
	CreateUC           *userUC.CreateUC
	GetAllUC           *userUC.GetAllUC
	GetByEmailUC       *userUC.GetByEmailUC
	GetByIdUC          *userUC.GetByIdUC
	LvlUpUC            *userUC.LvlUpUC
	UpdateUC           *userUC.UpdateUC
	IssueTokenUC       *jwtTokenUC.IssueTokenUC
	GetByUsernameUC    *userUC.GetByUsernameUC
	GetLikedFolkloreUC *folkloreUC.GetLikedUC
	cfg                *config.Config
}

func NewUserHandler(
	createUC *userUC.CreateUC,
	getAllUC *userUC.GetAllUC,
	getByEmailUC *userUC.GetByEmailUC,
	getByIdUC *userUC.GetByIdUC,
	lvlUpUC *userUC.LvlUpUC,
	updateUC *userUC.UpdateUC,
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

func (h *UserHandler) UpdateMe(c *gin.Context) {
	logger.Info("UpdateMe request started",
		zap.String("ip", c.ClientIP()),
	)

	var body dto.UserUpdatableFields
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("UpdateMe failed - invalid body",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	if body.Password != nil {
		logger.Warn("UpdateMe attempt to change password ignored")
		body.Password = nil
	}

	id, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("UpdateMe failed - cannot get user ID",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("UpdateMe executing update",
		zap.Int("user_id", int(*id)),
	)

	upd := models.UserUpdatableFields{
		Username: body.Username,
		Avatar:   body.Avatar,
		Role:     body.Role,
	}

	user, err := h.UpdateUC.Execute(c.Request.Context(), *id, upd)
	if err != nil {
		logger.Error("UpdateMe failed during update",
			zap.Int("user_id", int(*id)),
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("UpdateMe success",
		zap.Int("user_id", int(*id)),
	)

	response.Success(c, 200, dtoMappers.UserToDto(*user))
}

func (h *UserHandler) UpdateByAdmin(c *gin.Context) {
	logger.Info("Admin update user started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Warn("UpdateByAdmin failed - invalid ID param",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	var body dto.UserUpdatableFields
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("UpdateByAdmin failed - invalid body",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	logger.Info("UpdateByAdmin executing update",
		zap.Int("target_user_id", int(*id)),
	)

	upd := models.UserUpdatableFields{
		Username: body.Username,
		Avatar:   body.Avatar,
		Role:     body.Role,
		Password: body.Password,
	}

	user, err := h.UpdateUC.Execute(c.Request.Context(), *id, upd)
	if err != nil {
		logger.Error("UpdateByAdmin failed",
			zap.Int("target_user_id", int(*id)),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("UpdateByAdmin success",
		zap.Int("target_user_id", int(*id)),
	)

	response.Success(c, 200, dtoMappers.UserToDto(*user))
}

func (h *UserHandler) GetAllUsers(c *gin.Context) {
	logger.Info("GetAllUsers request")

	users, err := h.GetAllUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("GetAllUsers failed",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("GetAllUsers success",
		zap.Int("count", len(users)),
	)

	var dtoUsers []dto.User
	for _, u := range users {
		dtoUsers = append(dtoUsers, dtoMappers.UserToDto(u))
	}

	response.Success(c, 200, dtoUsers)
}

func (h *UserHandler) GetLikedFolklore(c *gin.Context) {
	logger.Info("GetLikedFolklore request")

	id, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("GetLikedFolklore failed - no user ID",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	folk, err := h.GetLikedFolkloreUC.Execute(c.Request.Context(), *id)

	if len(folk) == 0 {
		logger.Warn("GetLikedFolklore - no records found",
			zap.Int("user_id", int(*id)),
		)
		response.HandleDomainError(c, errs.ErrNotFound)
		return
	}

	if err != nil {
		logger.Error("GetLikedFolklore failed",
			zap.Int("user_id", int(*id)),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("GetLikedFolklore success",
		zap.Int("user_id", int(*id)),
		zap.Int("count", len(folk)),
	)

	response.Success(c, 200, folk)
}

func (h *UserHandler) GetUserByID(c *gin.Context) {
	logger.Info("GetUserByID request")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Warn("GetUserByID failed - invalid ID",
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	user, err := h.GetByIdUC.Execute(c, *id)
	if err != nil {
		logger.Error("GetUserByID failed",
			zap.Int("user_id", int(*id)),
			zap.Error(err),
		)
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("GetUserByID success",
		zap.Int("user_id", int(*id)),
	)

	response.Success(c, 200, user)
}

func (h *UserHandler) LevelUp(c *gin.Context) {
	logger.Info("LevelUp request started")

	id, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("LevelUp failed - cannot get user ID",
			zap.Error(err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	xpParam := c.Param("xp")
	xp, err := strconv.Atoi(xpParam)

	if err != nil {
		logger.Error("LevelUp failed - invalid XP param",
			zap.String("xp_param", xpParam),
			zap.Error(err),
		)
		log.Printf("[FOLKLORE][LevelUp] Error: %+v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
		return
	}

	logger.Info("LevelUp executing",
		zap.Int("user_id", int(*id)),
		zap.Int("xp_added", xp),
	)

	lvlRet := h.LvlUpUC.Execute(c.Request.Context(), *id, xp)

	if lvlRet.Err != nil {
		logger.Error("LevelUp failed during execution",
			zap.Int("user_id", int(*id)),
			zap.Error(lvlRet.Err),
		)
		response.HandleDomainError(c, errs.ErrInternal)
		return
	}

	logger.Info("LevelUp success",
		zap.Int("user_id", int(*id)),
		zap.Bool("is_level_up", lvlRet.IsLvlUp),
		zap.Int("prev_xp", lvlRet.PrevXp),
		zap.Int("prev_level", lvlRet.PrevLevel),
	)

	response.Success(c, 200, lvlRet.User, gin.H{
		"isLvlUp":   lvlRet.IsLvlUp,
		"prevXp":    lvlRet.PrevXp,
		"prevLevel": lvlRet.PrevLevel,
	})
}
