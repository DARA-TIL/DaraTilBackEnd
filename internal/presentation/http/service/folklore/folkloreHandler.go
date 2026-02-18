package folklore

import (
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type FolkloreHandler struct {
	CreateUC     *folkloreUC.CreateUC
	UpdateUC     *folkloreUC.UpdateUC
	GetByIdUC    *folkloreUC.GetByIDUC
	DeleteUC     *folkloreUC.DeleteUC
	GetByQueryUC *folkloreUC.GetByQueryUC
	GetAllUC     *folkloreUC.GetAllUC
	ToggleLikeUC *folkloreUC.ToggleLikeUC
	GetLikedUC   *folkloreUC.GetLikedUC
}

func NewFolkloreHandler(
	createUC *folkloreUC.CreateUC,
	updateUC *folkloreUC.UpdateUC,
	getByIdUC *folkloreUC.GetByIDUC,
	deleteUC *folkloreUC.DeleteUC,
	queryUC *folkloreUC.GetByQueryUC,
	getAllUC *folkloreUC.GetAllUC,
	toggleLikeUC *folkloreUC.ToggleLikeUC,
	getLikedUC *folkloreUC.GetLikedUC,
) *FolkloreHandler {

	return &FolkloreHandler{
		CreateUC:     createUC,
		UpdateUC:     updateUC,
		GetByIdUC:    getByIdUC,
		DeleteUC:     deleteUC,
		GetByQueryUC: queryUC,
		GetAllUC:     getAllUC,
		ToggleLikeUC: toggleLikeUC,
		GetLikedUC:   getLikedUC,
	}
}

func (h *FolkloreHandler) Create(c *gin.Context) {
	logger.Info("Create folklore request started")

	var body dto.FolkloreDTO
	err := c.ShouldBind(&body)
	if err != nil {
		logger.Warn("Invalid folklore input")
		response.HandleDomainError(c, domErr.ErrInvalidInput)
		return
	}

	domainFolklore := dtoMappers.DtoFolkloreToDomain(body)

	folk, err := h.CreateUC.Execute(c.Request.Context(), domainFolklore)
	if err != nil {
		logger.Error("Failed to create folklore")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore created successfully")
	folkDto := dtoMappers.FolkloreToDto(*folk)
	response.Success(c, 200, folkDto)
}

func (h *FolkloreHandler) Update(c *gin.Context) {
	logger.Info("Update folklore request started")

	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid folklore ID in update")
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	var body dto.UpdatableFolkloreFieldsDTO
	updFields := dtoMappers.DtoUpdatableFolkloreToDomain(body)

	folk, err := h.UpdateUC.Execute(c.Request.Context(), *idInt, updFields)
	if err != nil {
		logger.Error("Failed to update folklore")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore updated successfully")
	folkDto := dtoMappers.FolkloreToDto(*folk)
	response.Success(c, 200, folkDto)
}

func (h *FolkloreHandler) GetByID(c *gin.Context) {
	logger.Info("Get folklore by ID request started")

	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid folklore ID")
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	folk, err := h.GetByIdUC.Execute(c.Request.Context(), *idInt)
	if err != nil {
		logger.Error("Failed to get folklore by ID")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore retrieved successfully")
	folkDto := dtoMappers.FolkloreToDto(*folk)
	response.Success(c, 200, folkDto)
}

func (h *FolkloreHandler) Delete(c *gin.Context) {
	logger.Info("Delete folklore request started")

	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid folklore ID for delete")
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	err = h.DeleteUC.Execute(c.Request.Context(), *idInt)
	if err != nil {
		logger.Error("Failed to delete folklore")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore deleted successfully")
	response.Success(c, 200, "record deleted")
}

func (h *FolkloreHandler) GetAll(c *gin.Context) {
	logger.Info("Get all folklore request started")

	folk, err := h.GetAllUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("Failed to get all folklore")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore list retrieved successfully")

	var folkDto []dto.FolkloreDTO
	for _, f := range folk {
		fd := dtoMappers.FolkloreToDto(f)
		folkDto = append(folkDto, fd)
	}
	response.Success(c, 200, folkDto)
}

func (h *FolkloreHandler) ToggleLike(c *gin.Context) {
	logger.Info("Toggle like request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid folklore ID in toggle like")
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Warn("Unauthorized toggle like attempt")
		response.HandleDomainError(c, err)
		return
	}

	folk, isLiked, err := h.ToggleLikeUC.Execute(c.Request.Context(), *id, *userID)
	if err != nil {
		logger.Error("Failed to toggle like")
		response.HandleDomainError(c, err)
		return
	}

	if isLiked {
		logger.Info("Folklore liked successfully")
	} else {
		logger.Info("Folklore unliked successfully")
	}

	folkDto := dtoMappers.FolkloreToDto(*folk)
	response.Success(c, 200, folkDto, gin.H{"liked": isLiked})
}

func (h *FolkloreHandler) GetLikedFolklore(c *gin.Context) {
	logger.Info("Get liked folklore request started")

	id, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Warn("Unauthorized access to liked folklore")
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	folklore, err := h.GetLikedUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to retrieve liked folklore")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Liked folklore retrieved successfully")

	var folkDto []dto.FolkloreDTO
	for _, f := range folklore {
		fd := dtoMappers.FolkloreToDto(f)
		folkDto = append(folkDto, fd)
	}
	response.Success(c, 200, folkDto)
}

func (h *FolkloreHandler) GetByQuery(c *gin.Context) {
	logger.Info("Get folklore by query request started")

	var filters models.FolkloreFilter
	if err := c.ShouldBindQuery(&filters); err != nil {
		logger.Warn("Invalid query parameters for folklore search")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	folk, err := h.GetByQueryUC.Execute(c.Request.Context(), filters)
	if err != nil {
		logger.Error("Failed to execute folklore query")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Folklore query executed successfully")

	var folkDto []dto.FolkloreDTO
	for _, f := range folk {
		fd := dtoMappers.FolkloreToDto(f)
		folkDto = append(folkDto, fd)
	}
	response.Success(c, 200, folkDto)
}
