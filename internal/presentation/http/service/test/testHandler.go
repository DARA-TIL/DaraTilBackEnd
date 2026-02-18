package test

import (
	"DaraTilBackendV2/internal/application/usecases/testUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
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
	checkAnswerUC          *testUC.CheckAnswerUC
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
	checkAnswerUC *testUC.CheckAnswerUC,
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
		checkAnswerUC:          checkAnswerUC,
	}
}
func (h *TestHandler) Create(c *gin.Context) {
	var body dto.Test
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	test, err := h.createUC.Execute(c.Request.Context(), dtoMappers.DtoTestToDomain(body))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 201, testDto)
}
func (h *TestHandler) CreateQuestion(c *gin.Context) {
	var body dto.Question
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	q, err := h.createQuestionUC.Execute(c.Request.Context(), dtoMappers.DtoQuestionToDomain(body))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	qDto := dtoMappers.QuestionToDto(*q)
	response.Success(c, 201, qDto)
}
func (h *TestHandler) CreateOption(c *gin.Context) {
	var body dto.QuestionOption
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	o, err := h.createOptionUC.Execute(c.Request.Context(), dtoMappers.DtoQuestionOptionToDomain(body))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	oDto := dtoMappers.QuestionOptionToDto(*o)
	response.Success(c, 201, oDto)
}
func (h *TestHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	err = h.deleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 204, "test deleted successfully")
}
func (h *TestHandler) DeleteQuestion(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	err = h.deleteQuestionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 204, "question deleted successfully")
}
func (h *TestHandler) DeleteOption(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	err = h.deleteOptionUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 204, "option deleted successfully")
}
func (h *TestHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	test, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 201, testDto)
}
func (h *TestHandler) GetByLessonID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	test, err := h.getByLessonIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 201, testDto)
}
func (h *TestHandler) UpdateQuestionOption(c *gin.Context) {
	var body dto.QuestionOptionsUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	upd := dtoMappers.DtoQuestionOptionsUpdateToDomain(body)
	opt, err := h.updateQuestionOptionUC.Execute(c.Request.Context(), upd)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	optDto := dtoMappers.QuestionOptionToDto(*opt)
	response.Success(c, 201, optDto)
}
func (h *TestHandler) UpdateQuestion(c *gin.Context) {
	var body dto.QuestionUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	upd := dtoMappers.DtoQuestionUpdateToDomain(body)
	q, err := h.updateQuestionUC.Execute(c.Request.Context(), upd)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	qDto := dtoMappers.QuestionToDto(*q)
	response.Success(c, 201, qDto)
}
func (h *TestHandler) UpdateTest(c *gin.Context) {
	var body dto.TestUpdate
	err := c.ShouldBindJSON(&body)
	if err != nil {
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	upd := dtoMappers.DtoTestUpdateToDomain(body)
	test, err := h.updateUC.Execute(c.Request.Context(), upd)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	testDto := dtoMappers.TestToDto(*test)
	response.Success(c, 201, testDto)
}
func (h *TestHandler) CheckAnswers(c *gin.Context) {

}
