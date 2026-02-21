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
