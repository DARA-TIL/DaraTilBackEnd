package dictionary

import (
	"DaraTilBackendV2/internal/application/usecases/dictionaryUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type DictionaryHandler struct {
	createUC  *dictionaryUC.CreateUC
	updateUC  *dictionaryUC.UpdateUC
	deleteUC  *dictionaryUC.DeleteUC
	getAllUC  *dictionaryUC.GetAllUC
	getByIDUC *dictionaryUC.GetByIDUC
	getWordUC *dictionaryUC.GetWordUC
}

func NewDictionaryHandler(
	createUC *dictionaryUC.CreateUC,
	updateUC *dictionaryUC.UpdateUC,
	deleteUC *dictionaryUC.DeleteUC,
	getAllUC *dictionaryUC.GetAllUC,
	getByIDUC *dictionaryUC.GetByIDUC,
	getWord *dictionaryUC.GetWordUC,
) *DictionaryHandler {
	return &DictionaryHandler{
		createUC:  createUC,
		updateUC:  updateUC,
		deleteUC:  deleteUC,
		getAllUC:  getAllUC,
		getByIDUC: getByIDUC,
		getWordUC: getWord,
	}
}

// Create godoc
// @Summary Create dictionary word
// @Description Create a new dictionary word
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.WordCreate true "Word create payload"
// @Success 201 {object} map[string]interface{}
// @Failure 422 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /dictionary/create [post]
func (h *DictionaryHandler) Create(c *gin.Context) {
	var body dto.WordCreate
	if err := c.ShouldBindJSON(&body); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	word := dtoMappers.DTOWordCreateToDomainModel(body)
	err := h.createUC.Execute(c.Request.Context(), word)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 201, "success")
}

// Update godoc
// @Summary Update dictionary word
// @Description Update existing dictionary word
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.Word true "Word update payload"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /dictionary/update [patch]
func (h *DictionaryHandler) Update(c *gin.Context) {
	var body dto.Word
	if err := c.ShouldBindJSON(&body); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	word := dtoMappers.DTOWordToDomainModel(body)
	err := h.updateUC.Execute(c.Request.Context(), word)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "success")
}

// Delete godoc
// @Summary Delete dictionary word
// @Description Delete dictionary word by id
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Word ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /dictionary/delete/{id} [delete]
func (h *DictionaryHandler) Delete(c *gin.Context) {
	wordID, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	err = h.deleteUC.Execute(c.Request.Context(), *wordID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "success")
}

// GetAll godoc
// @Summary Get all dictionary words
// @Description Get all dictionary words
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.Word
// @Failure 500 {object} map[string]interface{}
// @Router /dictionary/getAll [get]
func (h *DictionaryHandler) GetAll(c *gin.Context) {
	words, err := h.getAllUC.Execute(c.Request.Context())
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	wordsDto := dtoMappers.WordsToDTOModel(words)
	response.Success(c, 200, wordsDto)
}

// GetByID godoc
// @Summary Get dictionary word by id
// @Description Get dictionary word by id
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Word ID"
// @Success 200 {object} dto.Word
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /dictionary/getById/{id} [get]
func (h *DictionaryHandler) GetByID(c *gin.Context) {
	wordID, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	word, err := h.getByIDUC.Execute(c.Request.Context(), *wordID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, word)
}

// GetByWord godoc
// @Summary Get all meanings of the word
// @Description Get dictionary words
// @Tags Dictionary
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param word path string true "Original word"
// @Success 200 {array} dto.Word
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /dictionary/getByWord/{word} [get]
func (h *DictionaryHandler) GetByWord(c *gin.Context) {
	word := c.Param("word")
	words, err := h.getWordUC.Execute(c.Request.Context(), word)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	wordsDto := dtoMappers.WordsToDTOModel(words)
	response.Success(c, 200, wordsDto)
}
