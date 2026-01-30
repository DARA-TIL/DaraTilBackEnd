package folklore

import (
	"DaraTilBackendV2/internal/application/usecases/folkloreUC"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type HandlerFolklore struct {
	CreateUC     folkloreUC.CreateFolkloreUC
	UpdateUC     folkloreUC.UpdateFolkloreUC
	GetByIdUC    folkloreUC.GetFolkloreByIDUC
	DeleteUC     folkloreUC.DeleteFolkloreUC
	GetByQueryUC folkloreUC.GetFolkloreByQueryUC
	GetAllUC     folkloreUC.GetAllFolkloreUC
	ToggleLikeUC folkloreUC.ToggleLikeUC
	GetLikedUC   folkloreUC.GetLikedFolkloreUC
}

func NewHandlerFolklore(
	createUC folkloreUC.CreateFolkloreUC,
	updateUC folkloreUC.UpdateFolkloreUC,
	getByIdUC folkloreUC.GetFolkloreByIDUC,
	deleteUC folkloreUC.DeleteFolkloreUC,
	queryUC folkloreUC.GetFolkloreByQueryUC,
	getAllUC folkloreUC.GetAllFolkloreUC,
	toggleLikeUC folkloreUC.ToggleLikeUC,
	getLikedUC folkloreUC.GetLikedFolkloreUC,
) *HandlerFolklore {

	return &HandlerFolklore{
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

func (h *HandlerFolklore) Create(c *gin.Context) {
	var body dto.FolkloreDTO
	err := c.ShouldBind(&body)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInvalidInput)
		return
	}
	domainFolklore := dtoMappers.DtoFolkloreToDomain(body)
	folk, err := h.CreateUC.Execute(c.Request.Context(), domainFolklore)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, folk)
}

func (h *HandlerFolklore) Update(c *gin.Context) {
	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}
	var body dto.UpdatableFolkloreFieldsDTO
	updFields := dtoMappers.DtoUpdatableToDomain(body)
	folk, err := h.UpdateUC.Execute(c.Request.Context(), *idInt, updFields)
	if err != nil {
		response.HandleDomainError(c, err)
	}
	response.Success(c, 200, folk)
}

func (h *HandlerFolklore) GetByID(c *gin.Context) {
	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}

	folk, err := h.GetByIdUC.Execute(c.Request.Context(), *idInt)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, folk)
}

func (h *HandlerFolklore) Delete(c *gin.Context) {

	idInt, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}
	err = h.DeleteUC.Execute(c.Request.Context(), *idInt)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "record deleted")
}

func (h *HandlerFolklore) GetAll(c *gin.Context) {
	folk, err := h.GetAllUC.Execute(c.Request.Context())
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, folk)
}

func (h *HandlerFolklore) ToggleLike(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	folk, isLiked, err := h.ToggleLikeUC.Execute(c.Request.Context(), *id, int(*userID))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, folk, gin.H{"liked": isLiked})

}

func (h *HandlerFolklore) GetLikedFolklore(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, domErr.ErrInternal)
		return
	}
	folklore, err := h.GetLikedUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, folklore)
}
