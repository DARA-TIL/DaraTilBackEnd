package lesson

import (
	"DaraTilBackendV2/internal/application/usecases/lessonUC"
	"DaraTilBackendV2/internal/application/usecases/testUC"
	"DaraTilBackendV2/internal/application/usecases/userUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	LessonLocked    = "locked"
	LessonAvailable = "available"
	LessonPassed    = "passed"
)

type LessonHandler struct {
	createUC             *lessonUC.CreateUC
	createBlockUC        *lessonUC.CreateBlockUC
	deleteUC             *lessonUC.DeleteUC
	deleteBlockUC        *lessonUC.DeleteBlockUC
	getAllUC             *lessonUC.GetAllUC
	getByIDUC            *lessonUC.GetByIDUC
	updateUC             *lessonUC.UpdateUC
	updateBlockUC        *lessonUC.UpdateBlockUC
	checkAnswersUC       *testUC.CheckAnswersUC
	finishLessonUC       *lessonUC.FinishLessonUC
	getFinishedLessonsUC *lessonUC.GetFinishedLessonsUC
	getLessonResultsUC   *lessonUC.GetLessonResultsUC
	lvlUpUC              *userUC.LvlUpUC
	getUserByIDUC        *userUC.GetByIdUC
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
	checkAnswersUC *testUC.CheckAnswersUC,
	finishLessonUC *lessonUC.FinishLessonUC,
	getFinishedLessonsUC *lessonUC.GetFinishedLessonsUC,
	getLessonResultsUC *lessonUC.GetLessonResultsUC,
	getUserByIDUC *userUC.GetByIdUC,
	lvlUpUC *userUC.LvlUpUC,
) *LessonHandler {
	return &LessonHandler{
		createUC:             createUC,
		createBlockUC:        createBlockUC,
		deleteUC:             deleteUC,
		deleteBlockUC:        deleteBlockUC,
		getAllUC:             getAllUC,
		getByIDUC:            getByIDUC,
		updateUC:             updateUC,
		updateBlockUC:        updateBlockUC,
		checkAnswersUC:       checkAnswersUC,
		finishLessonUC:       finishLessonUC,
		getFinishedLessonsUC: getFinishedLessonsUC,
		getLessonResultsUC:   getLessonResultsUC,
		getUserByIDUC:        getUserByIDUC,
		lvlUpUC:              lvlUpUC,
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

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("Unauthorized access while getting lessons")
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	logger.Info("User ID successfully extracted")

	lessons, err := h.getAllUC.Execute(c.Request.Context())
	if err != nil {
		logger.Error("Failed to get lessons")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Lessons successfully fetched")

	user, err := h.getUserByIDUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("Failed to get user by ID")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("User successfully fetched")

	lesRes, err := h.getFinishedLessonsUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("Failed to get finished lessons")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Finished lessons successfully fetched")

	lesResMap := make(map[uint]dto.LessonResult)
	for _, res := range lesRes {
		dtoRes := dtoMappers.LessonResultToDTO(res)
		lesResMap[res.LessonID] = dtoRes
	}
	logger.Info("Finished lessons mapped by LessonID")

	lessonsDto := dtoMappers.LessonsToDTO(lessons)
	logger.Info("Lessons mapped to DTO")

	for i := range lessonsDto {

		if res, ok := lesResMap[lessonsDto[i].ID]; ok {
			r := res
			lessonsDto[i].BestResult = &r
			logger.Info("Best result assigned to lesson")
		}

		if lessonsDto[i].RequiredLevel > user.Progress.Level {
			lessonsDto[i].LessonStatus = LessonLocked
			logger.Info("Lesson status set to LOCKED")
			continue
		}

		if res, ok := lesResMap[lessonsDto[i].ID]; ok && res.Pass {
			lessonsDto[i].LessonStatus = LessonPassed
			logger.Info("Lesson status set to PASSED")
		} else {
			lessonsDto[i].LessonStatus = LessonAvailable
			logger.Info("Lesson status set to AVAILABLE")
		}
	}

	logger.Info("Lesson list retrieved successfully")
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
	logger.Info("Lesson ID successfully parsed from params")

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("Unauthorized access while getting lesson by ID")
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	logger.Info("User ID successfully extracted")
	user, err := h.getUserByIDUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		logger.Error("Failed to get user by ID")
		response.HandleDomainError(c, err)
	}
	lesson, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		logger.Error("Failed to get lesson by ID")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Lesson entity successfully fetched")

	if user.Progress.Level < lesson.RequiredLevel {
		response.Fail(c, http.StatusLocked, "User level is not enough for this lesson")
		logger.Info("User doesnt have enough level for this lesson")
		return
	}
	res, err := h.getLessonResultsUC.Execute(c.Request.Context(), *userID, *id)
	if err != nil {
		logger.Error("Failed to get lesson results for user")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Lesson results successfully fetched")

	var dtoRes []dto.LessonResult
	for _, r := range res {
		dtoRes = append(dtoRes, dtoMappers.LessonResultToDTO(r))
	}
	logger.Info("Lesson results mapped to DTO")

	dtoLesson := dtoMappers.LessonToDTO(*lesson)
	dtoLesson.Results = dtoRes

	logger.Info("Lesson retrieved successfully")
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

func (h *LessonHandler) FinishLesson(c *gin.Context) {
	logger.Info("Finish lesson request started")

	var body dto.UserAnswers
	err := c.ShouldBindJSON(&body)
	if err != nil {
		logger.Error("Failed to bind JSON in FinishLesson")
		response.HandleDomainError(c, errs.ErrBadRequest)
		return
	}
	logger.Info("User answers successfully parsed")

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("Unauthorized access in FinishLesson")
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	logger.Info("User ID successfully extracted")

	userAns := dtoMappers.DTOUserAnswersToDomain(body)
	logger.Info("User answers mapped to domain model")

	res, err := h.checkAnswersUC.Execute(c.Request.Context(), userAns)
	if err != nil {
		logger.Error("Failed to check user answers")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("User answers checked successfully")

	finLes, err := h.finishLessonUC.Execute(c.Request.Context(), *res)
	if err != nil {
		logger.Error("Failed to finish lesson")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Lesson finish record created")

	if !finLes.Pass {
		logger.Info("Lesson not passed, returning result without level up")
		response.Success(c, http.StatusOK, finLes)
		return
	}
	logger.Info("Lesson passed, proceeding with reward and level up")

	lesson, err := h.getByIDUC.Execute(c.Request.Context(), finLes.LessonID)
	if err != nil {
		logger.Error("Failed to get lesson for reward calculation")
		response.HandleDomainError(c, err)
		return
	}
	logger.Info("Lesson successfully fetched for reward processing")

	lvlUp := h.lvlUpUC.Execute(c.Request.Context(), *userID, lesson.Reward)
	if lvlUp.Err != nil {
		logger.Error("Level up processing failed")
		response.HandleDomainError(c, lvlUp.Err)
		return
	}
	logger.Info("Level up processing completed successfully")

	response.Success(c, 200, lvlUp.User, gin.H{
		"isLvlUp":   lvlUp.IsLvlUp,
		"prevXp":    lvlUp.PrevXp,
		"prevLevel": lvlUp.PrevLevel,
	})
}
