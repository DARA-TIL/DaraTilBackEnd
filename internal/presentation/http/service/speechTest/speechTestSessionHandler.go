package speechTest

import (
	"DaraTilBackendV2/internal/application/usecases/testSpeechUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"

	"github.com/gin-gonic/gin"
)

type SpeechTestSessionHandler struct {
	sessionUC *testSpeechUC.TestSpeechSessionUC
}

func NewSpeechTestSessionHandler(
	sessionUC *testSpeechUC.TestSpeechSessionUC,
) *SpeechTestSessionHandler {
	return &SpeechTestSessionHandler{
		sessionUC: sessionUC,
	}
}

// StartSession godoc
// @Summary Start speech test session
// @Description Start a new speech test session or return active session for current authenticated user
// @Tags Speech Test Session
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SpeechTestSessionResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /speech-test-session/start [post]
func (h *SpeechTestSessionHandler) StartSession(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	session, err := h.sessionUC.StartSession(c.Request.Context(), *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	sessionDto := dtoMappers.ToSpeechTestSessionResponse(*session)
	response.Success(c, 200, sessionDto)
}

// GetNextTest godoc
// @Summary Get next speech test
// @Description Get random speech test that has not been used in current active session
// @Tags Speech Test Session
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SpeechTestResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-test-session/next [get]
func (h *SpeechTestSessionHandler) GetNextTest(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	test, err := h.sessionUC.GetNextTest(c.Request.Context(), *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	testDto := dtoMappers.ToSpeechTestResponse(*test)
	response.Success(c, 200, testDto)
}

// CheckPronounce godoc
// @Summary Check speech pronunciation
// @Description Check user's audio pronunciation for selected speech test
// @Tags Speech Test Session
// @Accept multipart/form-data
// @Produce json
// @Security BearerAuth
// @Param test_id formData int true "Speech test ID"
// @Param audio formData file true "Audio file"
// @Success 200 {object} dto.CheckPronounceResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-test-session/check [post]
func (h *SpeechTestSessionHandler) CheckPronounce(c *gin.Context) {
	var req dto.CheckPronounceRequest

	err := c.ShouldBind(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	fileHeader, err := c.FormFile("audio")
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	file, err := fileHeader.Open()
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	defer file.Close()

	result, err := h.sessionUC.CheckPronounce(
		c.Request.Context(),
		*userID,
		req.TestID,
		file,
	)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	resultDto := dtoMappers.ToCheckPronounceResponse(*result)
	response.Success(c, 200, resultDto)
}

// EndSession godoc
// @Summary End speech test session
// @Description End active speech test session and give reward to current authenticated user
// @Tags Speech Test Session
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SpeechTestSessionResultResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /speech-test-session/end [post]
func (h *SpeechTestSessionHandler) EndSession(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	result, err := h.sessionUC.EndSession(c.Request.Context(), *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	resultDto := dtoMappers.ToSpeechTestSessionResultResponse(*result)
	response.Success(c, 200, resultDto)
}
