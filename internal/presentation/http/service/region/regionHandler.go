package region

import (
	"DaraTilBackendV2/internal/application/usecases/regionUC"
	"DaraTilBackendV2/internal/application/usecases/regionUC/regionTranslationsUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type RegionHandler struct {
	CreateRegionUC  *regionUC.CreateUC
	DeleteRegionUC  *regionUC.DeleteUC
	GetAllRegionUC  *regionUC.GetAllUC
	GetRegionByIDUC *regionUC.GetByIDUC
	UpdateRegionUC  *regionUC.UpdateUC
	CreateMultiUC   *regionUC.CreateMultiUC
	GetByCodeUC     *regionUC.GetByCodeUC

	// region translations
	CreateRegionTranslationUC   *regionTranslationsUC.CreateUC
	DeleteRegionTranslationUC   *regionTranslationsUC.DeleteUC
	GetRegionTranslationByIDUC  *regionTranslationsUC.GetByIDUC
	UpdateRegionTranslationsUC  *regionTranslationsUC.UpdateUC
	GetTranslationsByRegionIDUC *regionTranslationsUC.GetByRegionUC

	//user
	GetUserByIDUC *userUC.GetByIdUC
}

func NewRegionHandler(
	createRegionUC *regionUC.CreateUC,
	deleteRegionUC *regionUC.DeleteUC,
	getAllRegionUC *regionUC.GetAllUC,
	getRegionByIDUC *regionUC.GetByIDUC,
	updateRegionUC *regionUC.UpdateUC,
	createMultiUC *regionUC.CreateMultiUC,
	getByCodeUC *regionUC.GetByCodeUC,

	createRegionTranslationUC *regionTranslationsUC.CreateUC,
	deleteRegionTranslationUC *regionTranslationsUC.DeleteUC,
	getRegionTranslationByIDUC *regionTranslationsUC.GetByIDUC,
	updateRegionTranslationsUC *regionTranslationsUC.UpdateUC,
	getTranslationsByRegionIDUC *regionTranslationsUC.GetByRegionUC,
	getUserByIDUC *userUC.GetByIdUC,
) *RegionHandler {

	return &RegionHandler{
		CreateRegionUC:              createRegionUC,
		DeleteRegionUC:              deleteRegionUC,
		GetAllRegionUC:              getAllRegionUC,
		GetRegionByIDUC:             getRegionByIDUC,
		UpdateRegionUC:              updateRegionUC,
		CreateMultiUC:               createMultiUC,
		GetByCodeUC:                 getByCodeUC,
		CreateRegionTranslationUC:   createRegionTranslationUC,
		DeleteRegionTranslationUC:   deleteRegionTranslationUC,
		GetRegionTranslationByIDUC:  getRegionTranslationByIDUC,
		UpdateRegionTranslationsUC:  updateRegionTranslationsUC,
		GetTranslationsByRegionIDUC: getTranslationsByRegionIDUC,
		GetUserByIDUC:               getUserByIDUC,
	}
}

// CreateAllRegions godoc
// @Summary Create All pre-imported regions
// @Description Creates all regions.
// @Tags Region
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 201 {object} map[string]interface{} "Region created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/create [post]
func (h *RegionHandler) CreateAllRegions(c *gin.Context) {
	regions := utils.ReadKzGeoJson()
	regionsDom := dtoMappers.RegionsToDomain(regions)
	err := h.CreateMultiUC.Execute(c.Request.Context(), regionsDom)
	if err != nil {
		logger.Error("CreateAllRegions error", zap.Error(err))
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 201, "success")
}

// CreateRegion godoc
// @Summary Create region
// @Description Creates a new region.
// @Tags Region
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.Region true "Region payload"
// @Success 201 {object} map[string]interface{} "Region created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/create [post]
func (h *RegionHandler) CreateRegion(c *gin.Context) {
	var body dto.Region
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	region := dtoMappers.RegionToDomain(body)
	err = h.CreateRegionUC.Execute(c.Request.Context(), region)
	if err != nil {
		logger.Error("[REGION CREATE] Error occured while creating region: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("[REGION CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegion godoc
// @Summary Delete region
// @Description Deletes region by ID.
// @Tags Region
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 204 {object} map[string]interface{} "Region deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/delete/{id} [delete]
func (h *RegionHandler) DeleteRegion(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	err = h.DeleteRegionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION DELETE] Error occured while deleting region: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("[REGION DELETE] success")

	response.Success(c, http.StatusNoContent, "deleted")
}

// GetAllRegion godoc
// @Summary Get all regions
// @Description Returns list of regions. If user is not admin, locked regions are hidden based on user level.
// @Tags Region
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.Region "Regions list"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/getAll [get]
func (h *RegionHandler) GetAllRegion(c *gin.Context) {
	regions, err := h.GetAllRegionUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("[GET ALL REGIONS] Error occured while getting all regions:" + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	regionsDTO := dtoMappers.RegionsToDTO(regions)
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("[GET ALL REGIONS] Error occured while getting current user id: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	log.Print("USERID: ", *userID)
	user, err := h.GetUserByIDUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("[GET ALL REGIONS] Error occured while getting current user: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	log.Print("USER: ", user)
	if user.Role != "admin" {
		dtoMappers.CheckRegionsAvailability(regionsDTO, user.Progress.Level)
	}
	logger.Info("[GET ALL REGIONS] success")
	response.Success(c, http.StatusOK, regionsDTO)
}

// GetRegionByID godoc
// @Summary Get region by ID
// @Description Returns region by ID. Returns 423 if user level is too low.
// @Tags Region
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 200 {object} dto.Region "Region"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 423 {object} map[string]interface{} "User level too low"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/getById/{id} [get]
func (h *RegionHandler) GetRegionByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	region, err := h.GetRegionByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION GET] Error occured while getting region: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("[REGION GET] Error occured while getting current user id: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	user, err := h.GetUserByIDUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("[REGION GET] Error occured while getting current user: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	if user.Role != "admin" {
		if user.Progress.Level < region.RequiredLevel {
			logger.Warn("[REGION GET] Progress level is too low", zap.Uint("userID", user.ID))
			c.JSON(http.StatusLocked, gin.H{"data": "Progress level is too low"})
			return
		}
	}
	regionDto := dtoMappers.RegionToDTO(*region)
	logger.Info("[REGION GET] success")
	response.Success(c, http.StatusOK, regionDto)
}

// UpdateRegion godoc
// @Summary Update region
// @Description Updates region fields.
// @Tags Region
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.Region true "Region payload"
// @Success 200 {object} map[string]interface{} "Region updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/update [patch]
func (h *RegionHandler) UpdateRegion(c *gin.Context) {
	var body dto.Region
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	region := dtoMappers.RegionToDomain(body)
	err = h.UpdateRegionUC.Execute(c.Request.Context(), region)
	if err != nil {
		logger.Error("[REGION UPDATE] Error occured while updating region: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("[REGION UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// CreateRegionTranslation godoc
// @Summary Create region translation
// @Description Creates translation for region.
// @Tags RegionTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTranslation true "Region translation payload"
// @Success 201 {object} map[string]interface{} "Translation created"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/translation/create [post]
func (h *RegionHandler) CreateRegionTranslation(c *gin.Context) {
	var body dto.RegionTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRANSLATION CREATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	translation := dtoMappers.RegionTranslationToDomain(body)

	err = h.CreateRegionTranslationUC.Execute(c.Request.Context(), translation)
	if err != nil {
		logger.Error("[REGION TRANSLATION CREATE] Error occured while creating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRANSLATION CREATE] success")
	response.Success(c, http.StatusCreated, "success")
}

// DeleteRegionTranslation godoc
// @Summary Delete region translation
// @Description Deletes region translation by ID.
// @Tags RegionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 204 {object} map[string]interface{} "Translation deleted"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/translation/delete/{id} [delete]
func (h *RegionHandler) DeleteRegionTranslation(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRANSLATION DELETE] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.DeleteRegionTranslationUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRANSLATION DELETE] Error occured while deleting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRANSLATION DELETE] success")
	response.Success(c, http.StatusNoContent, "deleted")
}

// GetRegionTranslationByID godoc
// @Summary Get region translation by ID
// @Description Returns region translation by ID.
// @Tags RegionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Translation ID"
// @Success 200 {object} dto.RegionTranslation "Translation"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/translation/getById/{id} [get]
func (h *RegionHandler) GetRegionTranslationByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRANSLATION GET] Error occured while binding id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	translation, err := h.GetRegionTranslationByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRANSLATION GET] Error occured while getting translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	translationDTO := dtoMappers.RegionTranslationToDTO(*translation)

	logger.Info("[REGION TRANSLATION GET] success")
	response.Success(c, http.StatusOK, translationDTO)
}

// UpdateRegionTranslation godoc
// @Summary Update region translation
// @Description Updates translation for region.
// @Tags RegionTranslation
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RegionTranslation true "Translation payload"
// @Success 200 {object} map[string]interface{} "Translation updated"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/translation/update [patch]
func (h *RegionHandler) UpdateRegionTranslation(c *gin.Context) {
	var body dto.RegionTranslation

	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("[REGION TRANSLATION UPDATE] Error occured while binding body: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	translation := dtoMappers.RegionTranslationToDomain(body)

	err = h.UpdateRegionTranslationsUC.Execute(c.Request.Context(), translation)
	if err != nil {
		logger.Error("[REGION TRANSLATION UPDATE] Error occured while updating translation: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("[REGION TRANSLATION UPDATE] success")
	response.Success(c, http.StatusOK, "success")
}

// GetTranslationsByRegionID godoc
// @Summary Get translations by region ID
// @Description Returns all translations for a region.
// @Tags RegionTranslation
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 200 {array} dto.RegionTranslation "Translations"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/{id}/translations [get]
func (h *RegionHandler) GetTranslationsByRegionID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("[REGION TRANSLATIONS GET] Error occured while binding region id: " + err.Error())
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	translations, err := h.GetTranslationsByRegionIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("[REGION TRANSLATIONS GET] Error occured while getting translations: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}

	translationsDTO := dtoMappers.RegionTranslationsToDTO(translations)

	logger.Info("[REGION TRANSLATIONS GET] success")
	response.Success(c, http.StatusOK, translationsDTO)
}

// GetByCode godoc
// @Summary Get region by code
// @Description Returns region by code
// @Tags Region
// @Produce json
// @Security BearerAuth
// @Param id path int true "Region ID"
// @Success 200 {array} dto.Region "Region"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /region/getByCode/{code} [get]
func (h *RegionHandler) GetByCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		logger.Error("Invalid request parameter")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	region, err := h.GetByCodeUC.Execute(c.Request.Context(), code)
	if err != nil {
		logger.Error("error occured while getting region: " + err.Error())
		response.HandleDomainError(c, err)
		return
	}
	regionDTO := dtoMappers.RegionToDTO(*region)
	response.Success(c, http.StatusOK, regionDTO)

}
