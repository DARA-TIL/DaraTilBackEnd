package region

import (
	"DaraTilBackendV2/internal/application/usecases/regionSlangUC"
	regionSlangTranslationUC "DaraTilBackendV2/internal/application/usecases/regionSlangUC/regionSlangTranslationsUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type RegionSlangHandler struct {
	// region slang
	CreateRegionSlangUC  *regionSlangUC.CreateUC
	DeleteRegionSlangUC  *regionSlangUC.DeleteUC
	GetRegionSlangByIDUC *regionSlangUC.GetByIDUC
	UpdateRegionSlangUC  *regionSlangUC.UpdateUC
	GetSlangByRegionIDUC *regionSlangUC.GetByRegionUC

	// region slang translations
	CreateRegionSlangTranslationUC  *regionSlangTranslationUC.CreateUC
	DeleteRegionSlangTranslationUC  *regionSlangTranslationUC.DeleteUC
	GetRegionSlangTranslationByIDUC *regionSlangTranslationUC.GetByIDUC
	UpdateRegionSlangTranslationUC  *regionSlangTranslationUC.UpdateUC
	GetSlangTranslationsBySlangIDUC *regionSlangTranslationUC.GetBySlangIDUC
}

func NewRegionSlangHandler(
	createRegionSlangUC *regionSlangUC.CreateUC,
	deleteRegionSlangUC *regionSlangUC.DeleteUC,
	getRegionSlangByIDUC *regionSlangUC.GetByIDUC,
	updateRegionSlangUC *regionSlangUC.UpdateUC,
	getSlangByRegionIDUC *regionSlangUC.GetByRegionUC,

	createRegionSlangTranslationUC *regionSlangTranslationUC.CreateUC,
	deleteRegionSlangTranslationUC *regionSlangTranslationUC.DeleteUC,
	getRegionSlangTranslationByIDUC *regionSlangTranslationUC.GetByIDUC,
	updateRegionSlangTranslationUC *regionSlangTranslationUC.UpdateUC,
	getSlangTranslationsBySlangIDUC *regionSlangTranslationUC.GetBySlangIDUC,
) *RegionSlangHandler {

	return &RegionSlangHandler{
		CreateRegionSlangUC:             createRegionSlangUC,
		DeleteRegionSlangUC:             deleteRegionSlangUC,
		GetRegionSlangByIDUC:            getRegionSlangByIDUC,
		UpdateRegionSlangUC:             updateRegionSlangUC,
		GetSlangByRegionIDUC:            getSlangByRegionIDUC,
		CreateRegionSlangTranslationUC:  createRegionSlangTranslationUC,
		DeleteRegionSlangTranslationUC:  deleteRegionSlangTranslationUC,
		GetRegionSlangTranslationByIDUC: getRegionSlangTranslationByIDUC,
		UpdateRegionSlangTranslationUC:  updateRegionSlangTranslationUC,
		GetSlangTranslationsBySlangIDUC: getSlangTranslationsBySlangIDUC,
	}
}

// CreateRegionSlang godoc
// @Summary Create region slang
// @Description Creates slang entry for region.
// @Tags RegionSlang
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionSlang true "Region slang payload"
// @Success 201 {object} map[string]interface{} "Slang created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/create [post]
func (h *RegionSlangHandler) CreateRegionSlang(c *gin.Context) {
	var body dto.RegionSlang

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION SLANG CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	slang := dtoMappers.RegionSlangToDomain(body)

	err = h.CreateRegionSlangUC.Execute(c.Request.Context(), slang)
	if err != nil {
		logger.Error("[REGION SLANG CREATE] Error occured while creating slang: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegionSlang godoc
// @Summary Delete region slang
// @Description Deletes region slang by ID.
// @Tags RegionSlang
// @Produce json
// @Security BearerAuth
// @Param id path int true "Slang ID"
// @Success 204 {object} map[string]interface{} "Slang deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/delete/{id} [delete]
func (h *RegionSlangHandler) DeleteRegionSlang(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.DeleteRegionSlangUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG DELETE] Error occured while deleting slang: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG DELETE] success")
	response.Success(c, http.StatusNoContent, "deleted")
}

// GetRegionSlangByID godoc
// @Summary Get region slang by ID
// @Description Returns slang entry by ID.
// @Tags RegionSlang
// @Produce json
// @Security BearerAuth
// @Param id path int true "Slang ID"
// @Success 200 {object} dto.RegionSlang "Region slang"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/getById/{id} [get]
func (h *RegionSlangHandler) GetRegionSlangByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	slang, err := h.GetRegionSlangByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG GET] Error occured while getting slang: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	slangDTO := dtoMappers.RegionSlangToDTO(*slang)

	logger.Info("[REGION SLANG GET] success")
	response.Success(c, http.StatusOK, slangDTO)
}

// UpdateRegionSlang godoc
// @Summary Update region slang
// @Description Updates region slang.
// @Tags RegionSlang
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionSlang true "Region slang payload"
// @Success 200 {object} map[string]interface{} "Slang updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/update [patch]
func (h *RegionSlangHandler) UpdateRegionSlang(c *gin.Context) {
	var body dto.RegionSlang

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION SLANG UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	slang := dtoMappers.RegionSlangToDomain(body)

	err = h.UpdateRegionSlangUC.Execute(c.Request.Context(), slang)
	if err != nil {
		logger.Error("[REGION SLANG UPDATE] Error occured while updating slang: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// GetSlangByRegionID godoc
// @Summary Get slang by region ID
// @Description Returns all slang entries for region.
// @Tags RegionSlang
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 200 {array} dto.RegionSlang "Slang list"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/{id}/slang [get]
func (h *RegionSlangHandler) GetSlangByRegionID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG GET] Error occured while binding region id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	slangs, err := h.GetSlangByRegionIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG GET] Error occured while getting slangs: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	slangsDTO := dtoMappers.RegionSlangsToDTO(slangs)

	logger.Info("[REGION SLANG GET] success")
	response.Success(c, http.StatusOK, slangsDTO)
}

// CreateRegionSlangTranslation godoc
// @Summary Create slang translation
// @Description Creates translation for region slang.
// @Tags RegionSlangTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionSlangTranslation true "Slang translation payload"
// @Success 201 {object} map[string]interface{} "Translation created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/translation/create [post]
func (h *RegionSlangHandler) CreateRegionSlangTranslation(c *gin.Context) {
	var body dto.RegionSlangTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr := dtoMappers.RegionSlangTranslationToDomain(body)

	err = h.CreateRegionSlangTranslationUC.Execute(c.Request.Context(), tr)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION CREATE] Error occured while creating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG TRANSLATION CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegionSlangTranslation godoc
// @Summary Delete slang translation
// @Description Deletes slang translation by ID.
// @Tags RegionSlangTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 204 {object} map[string]interface{} "Translation deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/translation/delete/{id} [delete]
func (h *RegionSlangHandler) DeleteRegionSlangTranslation(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.DeleteRegionSlangTranslationUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION DELETE] Error occured while deleting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG TRANSLATION DELETE] success")
	response.Success(c, http.StatusNoContent, "deleted")
}

// GetRegionSlangTranslationByID godoc
// @Summary Get slang translation by ID
// @Description Returns slang translation by ID.
// @Tags RegionSlangTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 200 {object} dto.RegionSlangTranslation "Slang translation"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/translation/getById/{id} [get]
func (h *RegionSlangHandler) GetRegionSlangTranslationByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr, err := h.GetRegionSlangTranslationByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION GET] Error occured while getting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	trDTO := dtoMappers.RegionSlangTranslationToDTO(*tr)

	logger.Info("[REGION SLANG TRANSLATION GET] success")
	response.Success(c, http.StatusOK, trDTO)
}

// UpdateRegionSlangTranslation godoc
// @Summary Update slang translation
// @Description Updates slang translation.
// @Tags RegionSlangTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionSlangTranslation true "Slang translation payload"
// @Success 200 {object} map[string]interface{} "Translation updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/translation/update [patch]
func (h *RegionSlangHandler) UpdateRegionSlangTranslation(c *gin.Context) {
	var body dto.RegionSlangTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	tr := dtoMappers.RegionSlangTranslationToDomain(body)

	err = h.UpdateRegionSlangTranslationUC.Execute(c.Request.Context(), tr)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATION UPDATE] Error occured while updating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION SLANG TRANSLATION UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// GetSlangTranslationsBySlangID godoc
// @Summary Get slang translations by slang ID
// @Description Returns all translations for slang.
// @Tags RegionSlangTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Slang ID"
// @Success 200 {array} dto.RegionSlangTranslation "Translations"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/slang/{id}/translations [get]
func (h *RegionSlangHandler) GetSlangTranslationsBySlangID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATIONS GET] Error occured while binding slang id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	translations, err := h.GetSlangTranslationsBySlangIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION SLANG TRANSLATIONS GET] Error occured while getting translations: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	trDTO := dtoMappers.RegionSlangTranslationsToDTO(translations)

	logger.Info("[REGION SLANG TRANSLATIONS GET] success")
	response.Success(c, http.StatusOK, trDTO)
}
