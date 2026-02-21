package test

import (
	"DaraTilBackendV2/internal/application/usecases/testUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type TestHandler struct {
	createUC               *testUC.CreateUC
	createQuestionUC       *testUC.CreateQuestionUC
	createOptionUC         *testUC.CreateOptionUC
	deleteOptionUC         *testUC.DeleteOptionUC
	deleteQuestionUC       *testUC.DeleteQuestionUC
	deleteUC               *testUC.DeleteUC
	getByIDUC              *testUC.GetByIDUC
	getByLessonIDUC        *testUC.GetByLessonIDUC
	updateQuestionOptionUC *testUC.UpdateQuestionOptionUC
	updateQuestionUC       *testUC.UpdateQuestionUC
	updateUC               *testUC.UpdateUC
}

func NewTestHandler(
	createUC *testUC.CreateUC,
	createQuestionUC *testUC.CreateQuestionUC,
	createOptionUC *testUC.CreateOptionUC,
	deleteOptionUC *testUC.DeleteOptionUC,
	deleteQuestionUC *testUC.DeleteQuestionUC,
	deleteUC *testUC.DeleteUC,
	getByIDUC *testUC.GetByIDUC,
	getByLessonIDUC *testUC.GetByLessonIDUC,
	updateQuestionOptionUC *testUC.UpdateQuestionOptionUC,
	updateQuestionUC *testUC.UpdateQuestionUC,
	updateUC *testUC.UpdateUC,
) *TestHandler {
	return &TestHandler{
		createUC:               createUC,
		createQuestionUC:       createQuestionUC,
		createOptionUC:         createOptionUC,
		deleteOptionUC:         deleteOptionUC,
		deleteQuestionUC:       deleteQuestionUC,
		deleteUC:               deleteUC,
		getByIDUC:              getByIDUC,
		getByLessonIDUC:        getByLessonIDUC,
		updateQuestionOptionUC: updateQuestionOptionUC,
		updateQuestionUC:       updateQuestionUC,
		updateUC:               updateUC,
	}
}

// Create godoc
// @Summary Create test
// @Description Creates a test with questions/options payload.
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.Test true "Test payload"
// @Success 201 {object} dto.Test "Created test"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/create [post]
func (h *TestHandler) Create(c *gin.Context) {
	logger.Info("Create test request started")

	var body dto.Test
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in Create test")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	logger.Info("Test body successfully parsed")

	test, err := h.createUC.Execute(c.Request.Context(), dtoMappers.DtoTestToDomain(body))
	if err != nil {
		logger.Error("Failed to create test")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Test successfully created")

	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 201, testDto)
}

// CreateQuestion godoc
// @Summary Create question
// @Description Creates a question for a test.
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.Question true "Question payload"
// @Success 201 {object} dto.Question "Created question"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/question/create [post]
func (h *TestHandler) CreateQuestion(c *gin.Context) {
	logger.Info("Create question request started")

	var body dto.Question
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in CreateQuestion")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	logger.Info("Question body successfully parsed")

	q, err := h.createQuestionUC.Execute(c.Request.Context(), dtoMappers.DtoQuestionToDomain(body))
	if err != nil {
		logger.Error("Failed to create question")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Question successfully created")

	qDto := dtoMappers.QuestionToDto(*q)
	response.Success(c, 201, qDto)
}

// CreateOption godoc
// @Summary Create question option
// @Description Creates an option for a question.
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.QuestionOption true "Option payload"
// @Success 201 {object} dto.QuestionOption "Created option"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/option/create [post]
func (h *TestHandler) CreateOption(c *gin.Context) {
	logger.Info("Create option request started")

	var body dto.QuestionOption
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in CreateOption")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	logger.Info("Option body successfully parsed")

	o, err := h.createOptionUC.Execute(c.Request.Context(), dtoMappers.DtoQuestionOptionToDomain(body))
	if err != nil {
		logger.Error("Failed to create option")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Option successfully created")

	oDto := dtoMappers.QuestionOptionToDto(*o)
	response.Success(c, 201, oDto)
}

// Delete godoc
// @Summary Delete test
// @Description Deletes a test by ID.
// @Tags Test
// @Produce json
// @Security BearerAuth
// @Param id path int true "Test ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/delete/{id} [delete]
func (h *TestHandler) Delete(c *gin.Context) {
	logger.Info("Delete test request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid test ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.deleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to delete test")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Test successfully deleted")

	response.Success(c, 204, "test deleted successfully")
}

// DeleteQuestion godoc
// @Summary Delete question
// @Description Deletes a question by ID.
// @Tags Test
// @Produce json
// @Security BearerAuth
// @Param id path int true "Question ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/question/delete/{id} [delete]
func (h *TestHandler) DeleteQuestion(c *gin.Context) {
	logger.Info("Delete question request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid question ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.deleteQuestionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to delete question")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Question successfully deleted")

	response.Success(c, 204, "question deleted successfully")
}

// DeleteOption godoc
// @Summary Delete question option
// @Description Deletes an option by ID.
// @Tags Test
// @Produce json
// @Security BearerAuth
// @Param id path int true "Option ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/option/delete/{id} [delete]
func (h *TestHandler) DeleteOption(c *gin.Context) {
	logger.Info("Delete option request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid option ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.deleteOptionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to delete option")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Option successfully deleted")

	response.Success(c, 204, "option deleted successfully")
}

// GetByID godoc
// @Summary Get test by ID
// @Description Returns test with questions and options by test ID.
// @Tags Test
// @Produce json
// @Security BearerAuth
// @Param id path int true "Test ID"
// @Success 200 {object} dto.Test "Test"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/get/{id} [get]
func (h *TestHandler) GetByID(c *gin.Context) {
	logger.Info("Get test by ID request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid test ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	test, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to get test by ID")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Test successfully retrieved by ID")

	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 200, testDto)
}

// GetByLessonID godoc
// @Summary Get test by lesson ID
// @Description Returns test attached to a lesson by lesson ID.
// @Tags Test
// @Produce json
// @Security BearerAuth
// @Param id path int true "Lesson ID"
// @Success 200 {object} dto.Test "Test"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/lesson/{id} [get]
func (h *TestHandler) GetByLessonID(c *gin.Context) {
	logger.Info("Get test by lesson ID request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	test, err := h.getByLessonIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to get test by lesson ID")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Test successfully retrieved by lesson ID")

	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 200, testDto)
}

// UpdateQuestionOption godoc
// @Summary Update question option
// @Description Updates option fields like text and isCorrect (partial update via nullable fields).
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.QuestionOptionsUpdate true "Option update payload"
// @Success 200 {object} dto.QuestionOption "Updated option"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/option/update [put]
func (h *TestHandler) UpdateQuestionOption(c *gin.Context) {
	logger.Info("Update question option request started")

	var body dto.QuestionOptionsUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in UpdateQuestionOption")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	upd := dtoMappers.DtoQuestionOptionsUpdateToDomain(body)
	opt, err := h.updateQuestionOptionUC.Execute(c.Request.Context(), upd)
	if err != nil {
		logger.Error("Failed to update question option")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Question option successfully updated")

	optDto := dtoMappers.QuestionOptionToDto(*opt)
	response.Success(c, 200, optDto)
}

// UpdateQuestion godoc
// @Summary Update question
// @Description Updates question fields and optionally nested options (partial update via nullable fields).
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.QuestionUpdate true "Question update payload"
// @Success 200 {object} dto.Question "Updated question"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/question/update [put]
func (h *TestHandler) UpdateQuestion(c *gin.Context) {
	logger.Info("Update question request started")

	var body dto.QuestionUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in UpdateQuestion")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	upd := dtoMappers.DtoQuestionUpdateToDomain(body)
	q, err := h.updateQuestionUC.Execute(c.Request.Context(), upd)
	if err != nil {
		logger.Error("Failed to update question")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Question successfully updated")

	qDto := dtoMappers.QuestionToDto(*q)
	response.Success(c, 200, qDto)
}

// UpdateTest godoc
// @Summary Update test
// @Description Updates test reward and nested questions/options (partial update via nullable fields).
// @Tags Test
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.TestUpdate true "Test update payload"
// @Success 200 {object} dto.Test "Updated test"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /test/update [put]
func (h *TestHandler) UpdateTest(c *gin.Context) {
	logger.Info("Update test request started")

	var body dto.TestUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in UpdateTest")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	upd := dtoMappers.DtoTestUpdateToDomain(body)
	test, err := h.updateUC.Execute(c.Request.Context(), upd)
	if err != nil {
		logger.Error("Failed to update test")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Test successfully updated")

	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 200, testDto)
}
