package lesson

import (
	"DaraTilBackendV2/internal/application/usecases/lessonUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LessonHandler struct {
	createUC      *lessonUC.CreateUC
	createBlockUC *lessonUC.CreateBlockUC
	deleteUC      *lessonUC.DeleteUC
	deleteBlockUC *lessonUC.DeleteBlockUC
	getAllUC      *lessonUC.GetAllUC
	getByIDUC     *lessonUC.GetByIDUC
	updateUC      *lessonUC.UpdateUC
	updateBlockUC *lessonUC.UpdateBlockUC
}

func NewLessonHandler(
	createUC *lessonUC.CreateUC,
	createBlockUC *lessonUC.CreateBlockUC,
	deleteUC *lessonUC.DeleteUC,
	deleteBlockUC *lessonUC.DeleteBlockUC,
	getAllUC *lessonUC.GetAllUC,
	getByIDUC *lessonUC.GetByIDUC,
	updateUC *lessonUC.UpdateUC,
	updateBlockUC *lessonUC.UpdateBlockUC,
) *LessonHandler {
	return &LessonHandler{
		createUC:      createUC,
		createBlockUC: createBlockUC,
		deleteUC:      deleteUC,
		deleteBlockUC: deleteBlockUC,
		getAllUC:      getAllUC,
		getByIDUC:     getByIDUC,
		updateUC:      updateUC,
		updateBlockUC: updateBlockUC,
	}
}

func (h *LessonHandler) CreateLesson(c *gin.Context) {
	logger.Info("Create lesson request started")

	var body dto.LessonDTO
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Warn("Invalid lesson input")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	lesson := dtoMappers.LessonDTOToDomain(body)
	crLesson, err := h.createUC.Execute(c.Request.Context(), lesson)
	if err != nil {
		logger.Error("Failed to create lesson")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson created successfully")
	lessonDto := dtoMappers.LessonToDTO(*crLesson)
	response.Success(c, http.StatusCreated, lessonDto)
}

func (h *LessonHandler) GetLessons(c *gin.Context) {
	logger.Info("Get all lessons request started")

	lessons, err := h.getAllUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("Failed to get lessons")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson list retrieved successfully")
	lessonsDto := dtoMappers.LessonsToDTO(lessons)
	response.Success(c, http.StatusOK, lessonsDto)
}

func (h *LessonHandler) GetLessonByID(c *gin.Context) {
	logger.Info("Get lesson by ID request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson ID")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	lesson, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to get lesson by ID")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson retrieved successfully")
	dtoLesson := dtoMappers.LessonToDTO(*lesson)
	response.Success(c, http.StatusOK, dtoLesson)
}

func (h *LessonHandler) UpdateLesson(c *gin.Context) {
	logger.Info("Update lesson request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson ID for update")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	var body dto.UpdateLessonDTO
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("Invalid lesson update input")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	updFields := dtoMappers.UpdateLessonDTOToDomain(body)
	lesson, err := h.updateUC.Execute(c.Request.Context(), *id, updFields)
	if err != nil {
		logger.Error("Failed to update lesson")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson updated successfully")
	lessonDto := dtoMappers.LessonToDTO(*lesson)
	response.Success(c, http.StatusOK, lessonDto)
}

func (h *LessonHandler) DeleteLesson(c *gin.Context) {
	logger.Info("Delete lesson request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson ID for delete")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.deleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to delete lesson")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson deleted successfully")
	response.Success(c, http.StatusNoContent, "Lesson deleted successfully")
}

func (h *LessonHandler) CreateBlock(c *gin.Context) {
	logger.Info("Create lesson block request started")

	var body dto.LessonBlockDTO
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("Invalid lesson block input")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	cr := dtoMappers.LessonBlockDTOToDomain(body)
	bl, err := h.createBlockUC.Execute(c.Request.Context(), cr)
	if err != nil {
		logger.Error("Failed to create lesson block")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson block created successfully")
	blockDto := dtoMappers.LessonBlockToDTO(*bl)
	response.Success(c, http.StatusCreated, blockDto)
}

func (h *LessonHandler) DeleteBlock(c *gin.Context) {
	logger.Info("Delete lesson block request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson block ID for delete")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	err = h.deleteBlockUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to delete lesson block")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson block deleted successfully")
	response.Success(c, http.StatusNoContent, "Block deleted successfully")
}

func (h *LessonHandler) UpdateBlock(c *gin.Context) {
	logger.Info("Update lesson block request started")

	id, err := utils.GetIdFromParams(c)
	if err != nil {
		logger.Error("Invalid lesson block ID for update")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}

	var body dto.UpdateLessonBlockDTO
	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Warn("Invalid lesson block update input")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	if body.Position != nil {
		if body.LessonID == nil {
			response.Fail(c, http.StatusUnprocessableEntity, "lesson block position and lesson id is required")
			return
		}
	}
	upd := dtoMappers.UpdateLessonBlockDTOToDomain(body)
	bl, err := h.updateBlockUC.Execute(c.Request.Context(), *id, upd)
	if err != nil {
		logger.Error("Failed to update lesson block")
		response.HandleDomainError(c, err)
		return
	}

	logger.Info("Lesson block updated successfully")
	blockDto := dtoMappers.LessonBlockToDTO(*bl)
	response.Success(c, http.StatusOK, blockDto)
}
