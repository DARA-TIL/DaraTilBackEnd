package timeEvent

import (
	"DaraTilBackendV2/internal/application/usecases/timeEventParticipantUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

type TimeEventParticipantHandler struct {
	CreateUC               *timeEventParticipantUC.CreateUC
	UpdateUC               *timeEventParticipantUC.UpdateUC
	DeleteUC               *timeEventParticipantUC.DeleteUC
	GetEventParticipantUC  *timeEventParticipantUC.GetEventParticipantUC
	GetEventParticipantsUC *timeEventParticipantUC.GetEventParticipantsUC
}

func NewTimeEventParticipantHandler(
	createUC *timeEventParticipantUC.CreateUC,
	updateUC *timeEventParticipantUC.UpdateUC,
	deleteUC *timeEventParticipantUC.DeleteUC,
	getEventParticipantUC *timeEventParticipantUC.GetEventParticipantUC,
	getEventParticipantsUC *timeEventParticipantUC.GetEventParticipantsUC) *TimeEventParticipantHandler {
	return &TimeEventParticipantHandler{
		CreateUC:               createUC,
		UpdateUC:               updateUC,
		DeleteUC:               deleteUC,
		GetEventParticipantUC:  getEventParticipantUC,
		GetEventParticipantsUC: getEventParticipantsUC,
	}
}

// Create godoc
// @Summary Create time event participant
// @Description Creates a new participant for a time event.
// @Tags TimeEventParticipant
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.CreateTimeEventParticipantRequest true "Time event participant create payload"
// @Success 201 {object} dto.TimeEventParticipant "Created time event participant"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEventParticipant/ [post]
func (h *TimeEventParticipantHandler) Create(c *gin.Context) {
	var req dto.CreateTimeEventParticipantRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	if req.UserID == 0 || req.TimeEventID == 0 {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	participantModel := dtoMappers.TimeEventParticipantFromCreateRequest(req)

	participant, err := h.CreateUC.Execute(c.Request.Context(), participantModel)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	participantDto := dtoMappers.TimeEventParticipantToDto(*participant)
	response.Success(c, 201, participantDto)
}

// Update godoc
// @Summary Update time event participant
// @Description Updates time event participant fields. Partial update via nullable fields.
// @Tags TimeEventParticipant
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.UpdateTimeEventParticipantRequest true "Time event participant update payload"
// @Success 200 {object} dto.TimeEventParticipant "Updated time event participant"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEventParticipant/ [patch]
func (h *TimeEventParticipantHandler) Update(c *gin.Context) {
	var req dto.UpdateTimeEventParticipantRequest

	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	if req.ID == 0 {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	participantModel := dtoMappers.TimeEventParticipantFromUpdateRequest(req)

	participant, err := h.UpdateUC.Execute(c.Request.Context(), participantModel)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	participantDto := dtoMappers.TimeEventParticipantToDto(*participant)
	response.Success(c, 200, participantDto)
}

// Delete godoc
// @Summary Delete time event participant
// @Description Deletes a time event participant by ID.
// @Tags TimeEventParticipant
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event participant ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEventParticipant/{id} [delete]
func (h *TimeEventParticipantHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	err = h.DeleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 204, "deleted successfully")
}

// GetByID godoc
// @Summary Get time event participant by ID
// @Description Returns a time event participant by ID.
// @Tags TimeEventParticipant
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event participant ID"
// @Success 200 {object} dto.TimeEventParticipant "Time event participant"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEventParticipant/{id} [get]
func (h *TimeEventParticipantHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	participant, err := h.GetEventParticipantUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	participantDto := dtoMappers.TimeEventParticipantToDto(*participant)
	response.Success(c, 200, participantDto)
}

// GetByEventID godoc
// @Summary Get time event participants by event ID
// @Description Returns participants of a time event and updates their places.
// @Tags TimeEventParticipant
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event ID"
// @Param limit path int true "Maximum number of participants"
// @Success 200 {array} dto.TimeEventParticipant "List of time event participants"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEventParticipant/event/{id}/{limit} [get]
func (h *TimeEventParticipantHandler) GetByEventID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	lim := c.Param("limit")
	limInt, err := strconv.Atoi(lim)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	participants, err := h.GetEventParticipantsUC.Execute(c.Request.Context(), *id, limInt)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	participantsDto := dtoMappers.TimeEventParticipantsToDto(participants)
	response.Success(c, 200, participantsDto)
}
