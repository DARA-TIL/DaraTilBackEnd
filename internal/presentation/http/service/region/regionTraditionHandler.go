package region

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/regionTraditionsUC"
	"DaraTilBackendV2/internal/application/usecases/regionTraditionsUC/regionTraditionTranslationsUC"
	utils2 "DaraTilBackendV2/internal/application/utils"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type RegionTraditionHandler struct {
	// region traditions
	CreateRegionTraditionUC   *regionTraditionsUC.CreateUC
	DeleteRegionTraditionUC   *regionTraditionsUC.DeleteUC
	GetRegionTraditionByIDUC  *regionTraditionsUC.GetByIDUC
	UpdateRegionTraditionUC   *regionTraditionsUC.UpdateUC
	GetTraditionsByRegionIDUC *regionTraditionsUC.GetByRegionUC

	// region tradition translations
	CreateRegionTraditionTranslationUC      *regionTraditionTranslationsUC.CreateUC
	DeleteRegionTraditionTranslationUC      *regionTraditionTranslationsUC.DeleteUC
	GetRegionTraditionTranslationByIDUC     *regionTraditionTranslationsUC.GetByIDUC
	UpdateRegionTraditionTranslationUC      *regionTraditionTranslationsUC.UpdateUC
	GetTraditionTranslationsByTraditionIDUC *regionTraditionTranslationsUC.GetByTraditionIDUC
}

func NewRegionTraditionHandler(
	createRegionTraditionUC *regionTraditionsUC.CreateUC,
	deleteRegionTraditionUC *regionTraditionsUC.DeleteUC,
	getRegionTraditionByIDUC *regionTraditionsUC.GetByIDUC,
	updateRegionTraditionUC *regionTraditionsUC.UpdateUC,
	getTraditionsByRegionIDUC *regionTraditionsUC.GetByRegionUC,

	createRegionTraditionTranslationUC *regionTraditionTranslationsUC.CreateUC,
	deleteRegionTraditionTranslationUC *regionTraditionTranslationsUC.DeleteUC,
	getRegionTraditionTranslationByIDUC *regionTraditionTranslationsUC.GetByIDUC,
	updateRegionTraditionTranslationUC *regionTraditionTranslationsUC.UpdateUC,
	getTraditionTranslationsByTraditionIDUC *regionTraditionTranslationsUC.GetByTraditionIDUC,
) *RegionTraditionHandler {

	return &RegionTraditionHandler{
		CreateRegionTraditionUC:                 createRegionTraditionUC,
		DeleteRegionTraditionUC:                 deleteRegionTraditionUC,
		GetRegionTraditionByIDUC:                getRegionTraditionByIDUC,
		UpdateRegionTraditionUC:                 updateRegionTraditionUC,
		GetTraditionsByRegionIDUC:               getTraditionsByRegionIDUC,
		CreateRegionTraditionTranslationUC:      createRegionTraditionTranslationUC,
		DeleteRegionTraditionTranslationUC:      deleteRegionTraditionTranslationUC,
		GetRegionTraditionTranslationByIDUC:     getRegionTraditionTranslationByIDUC,
		UpdateRegionTraditionTranslationUC:      updateRegionTraditionTranslationUC,
		GetTraditionTranslationsByTraditionIDUC: getTraditionTranslationsByTraditionIDUC,
	}
}

// CreateRegionTradition godoc
// @Summary Create region tradition
// @Description Creates tradition entry for region.
// @Tags RegionTradition
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTraditions true "Region tradition payload"
// @Success 201 {object} map[string]interface{} "Tradition created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/create [post]
func (h *RegionTraditionHandler) CreateRegionTradition(c *gin.Context) {
	var body dto.RegionTraditions

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRADITION CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tradition := dtoMappers.RegionTraditionToDomain(body)

	err = h.CreateRegionTraditionUC.Execute(c.Request.Context(), tradition)
	if err != nil {
		logger.Error("[REGION TRADITION CREATE] Error occured while creating tradition: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegionTradition godoc
// @Summary Delete region tradition
// @Description Deletes region tradition by ID.
// @Tags RegionTradition
// @Produce json
// @Security BearerAuth
// @Param id path int true "Tradition ID"
// @Success 204 {object} map[string]interface{} "Tradition deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/delete/{id} [delete]
func (h *RegionTraditionHandler) DeleteRegionTradition(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITION DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.DeleteRegionTraditionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRADITION DELETE] Error occured while deleting tradition: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION DELETE] success")
	response.Success(c, http.StatusNoContent, "deleted")
}

// GetRegionTraditionByID godoc
// @Summary Get region tradition by ID
// @Description Returns tradition entry by ID.
// @Tags RegionTradition
// @Produce json
// @Security BearerAuth
// @Param id path int true "Tradition ID"
// @Success 200 {object} dto.GetTraditionResponse "Region tradition"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/getById/{id} [get]
func (h *RegionTraditionHandler) GetRegionTraditionByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITION GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	ctx := c.Request.Context()
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Warn("[REGION SLANG GET] Error getting user ID")
	}
	if userID != nil {
		ctx = utils2.WithUserID(ctx, *userID)
	}
	res, err := h.GetRegionTraditionByIDUC.Execute(ctx, *id)
	if err != nil {
		logger.Error("[REGION TRADITION GET] Error occured while getting tradition: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	traditionDTO := dtoMappers.RegionTraditionToDTO(*res.Tradition)
	resp := dto.GetTraditionResponse{
		Tradition: traditionDTO,
		Streak:    services.StreakResultToString(res.Streak),
	}
	logger.Info("[REGION TRADITION GET] success")
	response.Success(c, http.StatusOK, resp)
}

// UpdateRegionTradition godoc
// @Summary Update region tradition
// @Description Updates region tradition.
// @Tags RegionTradition
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTraditions true "Region tradition payload"
// @Success 200 {object} map[string]interface{} "Tradition updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/update [patch]
func (h *RegionTraditionHandler) UpdateRegionTradition(c *gin.Context) {
	var body dto.RegionTraditions

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRADITION UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tradition := dtoMappers.RegionTraditionToDomain(body)

	err = h.UpdateRegionTraditionUC.Execute(c.Request.Context(), tradition)
	if err != nil {
		logger.Error("[REGION TRADITION UPDATE] Error occured while updating tradition: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// GetTraditionsByRegionID godoc
// @Summary Get traditions by region ID
// @Description Returns all traditions for region.
// @Tags RegionTradition
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 200 {array} dto.RegionTraditions "Traditions list"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/{id}/traditions [get]
func (h *RegionTraditionHandler) GetTraditionsByRegionID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITIONS GET] Error occured while binding region id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	traditions, err := h.GetTraditionsByRegionIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRADITIONS GET] Error occured while getting traditions: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	traditionsDTO := dtoMappers.RegionTraditionsToDTO(traditions)

	logger.Info("[REGION TRADITIONS GET] success")
	response.Success(c, http.StatusOK, traditionsDTO)
}

// CreateRegionTraditionTranslation godoc
// @Summary Create tradition translation
// @Description Creates translation for region tradition.
// @Tags RegionTraditionTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTraditionsTranslation true "Tradition translation payload"
// @Success 201 {object} map[string]interface{} "Translation created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/translation/create [post]
func (h *RegionTraditionHandler) CreateRegionTraditionTranslation(c *gin.Context) {
	var body dto.RegionTraditionsTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr := dtoMappers.RegionTraditionTranslationToDomain(body)

	err = h.CreateRegionTraditionTranslationUC.Execute(c.Request.Context(), tr)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION CREATE] Error occured while creating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION TRANSLATION CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegionTraditionTranslation godoc
// @Summary Delete tradition translation
// @Description Deletes tradition translation by ID.
// @Tags RegionTraditionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 204 {object} map[string]interface{} "Translation deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/translation/delete/{id} [delete]
func (h *RegionTraditionHandler) DeleteRegionTraditionTranslation(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.DeleteRegionTraditionTranslationUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION DELETE] Error occured while deleting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION TRANSLATION DELETE] success")
	response.Success(c, http.StatusNoContent, "deleted")
}

// GetRegionTraditionTranslationByID godoc
// @Summary Get tradition translation by ID
// @Description Returns translation by ID.
// @Tags RegionTraditionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 200 {object} dto.RegionTraditionsTranslation "Tradition translation"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/translation/getById/{id} [get]
func (h *RegionTraditionHandler) GetRegionTraditionTranslationByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr, err := h.GetRegionTraditionTranslationByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION GET] Error occured while getting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	trDTO := dtoMappers.RegionTraditionTranslationToDTO(*tr)

	logger.Info("[REGION TRADITION TRANSLATION GET] success")
	response.Success(c, http.StatusOK, trDTO)
}

// UpdateRegionTraditionTranslation godoc
// @Summary Update tradition translation
// @Description Updates tradition translation.
// @Tags RegionTraditionTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTraditionsTranslation true "Tradition translation payload"
// @Success 200 {object} map[string]interface{} "Translation updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/tradition/translation/update [patch]
func (h *RegionTraditionHandler) UpdateRegionTraditionTranslation(c *gin.Context) {
	var body dto.RegionTraditionsTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr := dtoMappers.RegionTraditionTranslationToDomain(body)

	err = h.UpdateRegionTraditionTranslationUC.Execute(c.Request.Context(), tr)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATION UPDATE] Error occured while updating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRADITION TRANSLATION UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// GetTraditionTranslationsByTraditionID godoc
// @Summary Get tradition translations by tradition ID
// @Description Returns all translations for tradition.
// @Tags RegionTraditionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "TraditionID"
// @Success 200 {array} dto.RegionTraditionsTranslation "Translations list"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/{id}/traditions [get]
func (h *RegionTraditionHandler) GetTraditionTranslationsByTraditionID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATIONS GET] Error occured while binding tradition id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr, err := h.GetTraditionTranslationsByTraditionIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRADITION TRANSLATIONS GET] Error occured while getting translations: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	trDTO := dtoMappers.RegionTraditionsTranslationsToDTO(tr)

	logger.Info("[REGION TRADITION TRANSLATIONS GET] success")
	response.Success(c, http.StatusOK, trDTO)
}
