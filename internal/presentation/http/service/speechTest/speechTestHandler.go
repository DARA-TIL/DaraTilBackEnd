package speechTest

import (
	"DaraTilBackendV2/internal/application/usecases/testSpeechUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type SpeechTestHandler struct {
	speechTestUC *testSpeechUC.TestSpeechUC
}

func NewSpeechTestHandler(
	speechTestUC *testSpeechUC.TestSpeechUC,
) *SpeechTestHandler {
	return &SpeechTestHandler{
		speechTestUC: speechTestUC,
	}
}

// Create godoc
// @Summary Create speech test
// @Description Create a new speech pronunciation test
// @Tags Speech Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param testReq body dto.SpeechTestCreateRequest true "Speech test create request"
// @Success 201 {object} dto.SpeechTestResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /speech-tests [post]
func (h *SpeechTestHandler) Create(c *gin.Context) {
	var req dto.SpeechTestCreateRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	test := models.SpeechTest{
		KzText:     req.KzText,
		RuText:     req.RuText,
		EnText:     req.EnText,
		Difficulty: req.Difficulty,
	}

	created, err := h.speechTestUC.Create(c.Request.Context(), test)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	testDto := dtoMappers.ToSpeechTestResponse(*created)
	response.Success(c, 201, testDto)
}

// GetAll godoc
// @Summary Get all speech tests
// @Description Get all speech pronunciation tests
// @Tags Speech Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SpeechTestListResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /speech-tests [get]
func (h *SpeechTestHandler) GetAll(c *gin.Context) {
	tests, err := h.speechTestUC.GetAll(c.Request.Context())
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	testsDto := dtoMappers.ToSpeechTestResponses(tests)

	response.Success(c, 200, dto.SpeechTestListResponse{
		Items: testsDto,
		Total: len(testsDto),
	})
}

// GetByID godoc
// @Summary Get speech test by ID
// @Description Get one speech pronunciation test by ID
// @Tags Speech Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Speech test ID"
// @Success 200 {object} dto.SpeechTestResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-tests/{id} [get]
func (h *SpeechTestHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	test, err := h.speechTestUC.GetByID(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	testDto := dtoMappers.ToSpeechTestResponse(*test)
	response.Success(c, 200, testDto)
}

// Update godoc
// @Summary Update speech test
// @Description Update speech pronunciation test by ID
// @Tags Speech Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Speech test ID"
// @Param testReq body dto.SpeechTestUpdateRequest true "Speech test update request"
// @Success 200 {object} dto.SpeechTestResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-tests/{id} [put]
func (h *SpeechTestHandler) Update(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	var req dto.SpeechTestUpdateRequest

	err = c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	test := models.SpeechTest{
		KzText:     req.KzText,
		RuText:     req.RuText,
		EnText:     req.EnText,
		Difficulty: req.Difficulty,
	}

	updated, err := h.speechTestUC.Update(c.Request.Context(), *id, test)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	testDto := dtoMappers.ToSpeechTestResponse(*updated)
	response.Success(c, 200, testDto)
}

// Delete godoc
// @Summary Delete speech test
// @Description Delete speech pronunciation test by ID
// @Tags Speech Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Speech test ID"
// @Success 204 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-tests/{id} [delete]
func (h *SpeechTestHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	err = h.speechTestUC.Delete(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 204, "deleted successfully")
}
