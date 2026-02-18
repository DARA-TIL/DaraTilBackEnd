package test

import (
	"DaraTilBackendV2/internal/application/usecases/testUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"

	"github.com/gin-gonic/gin"
)

type TestHandler struct {
	createUC               *testUC.CreateUC
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
func (h *TestHandler) Delete(c *gin.Context) {

}
