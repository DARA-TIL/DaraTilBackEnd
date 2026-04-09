package assistant

import (
	"DaraTilBackendV2/internal/application/usecases/wordExpainUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Assistant struct {
	WordExplainUC *wordExpainUC.WordExplainUC
}

func NewAssistant(wordExplainUC *wordExpainUC.WordExplainUC) *Assistant {
	return &Assistant{
		WordExplainUC: wordExplainUC,
	}
}

// ExplainWord godoc
// @Summary Get Explaining of the word in its context
// @Description Explaining of the word in its context by the help of AI
// @Tags Assistant
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param wordReq body dto.WordExplain true "Word Request with its block"
// @Success 200 {object} dto.WordExplainResult
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /assistant/explainWord [post]
func (a *Assistant) ExplainWord(c *gin.Context) {
	var req dto.WordExplain
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	reqDom := dtoMappers.WordExplainToDomain(req)
	res, err := a.WordExplainUC.Explain(c.Request.Context(), reqDom)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	resFto := dtoMappers.WordExplainResultToDto(*res)
	response.Success(c, http.StatusOK, resFto)
}
