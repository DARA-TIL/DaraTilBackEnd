package timeEvent

import (
	"DaraTilBackendV2/internal/application/usecases/timeEventUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type TimeEventHandler struct {
	createUC          *timeEventUC.CreateUC
	updateUC          *timeEventUC.UpdateUC
	deleteUC          *timeEventUC.DeleteUC
	getByIDUC         *timeEventUC.GetByIDUC
	getAllUC          *timeEventUC.GetAllUC
	finishTimeEventUC *timeEventUC.FinishTimeEventUC
}

func NewTimeEventHandler(
	createUC *timeEventUC.CreateUC,
	updateUC *timeEventUC.UpdateUC,
	deleteUC *timeEventUC.DeleteUC,
	getByIDUC *timeEventUC.GetByIDUC,
	getAllUC *timeEventUC.GetAllUC,
	finishTimeEventUC *timeEventUC.FinishTimeEventUC) *TimeEventHandler {
	return &TimeEventHandler{
		createUC:          createUC,
		updateUC:          updateUC,
		deleteUC:          deleteUC,
		getByIDUC:         getByIDUC,
		getAllUC:          getAllUC,
		finishTimeEventUC: finishTimeEventUC,
	}
}

// Create godoc
// @Summary Create time event
// @Description Creates a new time event. Admin access required.
// @Tags TimeEvent
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.CreateTimeEventRequest true "Time event create payload"
// @Success 201 {object} dto.TimeEvent "Created time event"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/ [post]
func (h *TimeEventHandler) Create(c *gin.Context) {
	var req dto.CreateTimeEventRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if req.Status != nil {
		if *req.Status == models.Ended {
			response.Fail(c, http.StatusBadRequest, "status ended is not permitted")
			return
		}
	}
	e := dtoMappers.TimeEventFromCreateRequest(req)
	event, err := h.createUC.Execute(c.Request.Context(), e)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	eventDto := dtoMappers.TimeEventToDto(*event)
	response.Success(c, 201, eventDto)
}

// Update godoc
// @Summary Update time event
// @Description Updates time event fields. Partial update via nullable fields. Admin access required.
// @Tags TimeEvent
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.UpdateTimeEventRequest true "Time event update payload. Changing status to Ended is not permitted, use another route"
// @Success 200 {object} dto.TimeEvent "Updated time event"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/ [patch]
func (h *TimeEventHandler) Update(c *gin.Context) {
	var req dto.UpdateTimeEventRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if req.ID == 0 {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if req.Status != nil {
		if *req.Status == models.Ended {
			response.Fail(c, http.StatusBadRequest, "status ended is not permitted")
			return
		}
	}
	e := dtoMappers.TimeEventFromUpdateRequest(req)
	event, err := h.updateUC.Execute(c.Request.Context(), e)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	eventDto := dtoMappers.TimeEventToDto(*event)
	response.Success(c, 200, eventDto)
}

// Delete godoc
// @Summary Delete time event
// @Description Deletes a time event by ID. Admin access required.
// @Tags TimeEvent
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/{id} [delete]
func (h *TimeEventHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	err = h.deleteUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 204, "deleted successfully")
}

// GetByID godoc
// @Summary Get time event by ID
// @Description Returns a time event by ID.
// @Tags TimeEvent
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event ID"
// @Success 200 {object} dto.TimeEvent "Time event"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/{id} [get]
func (h *TimeEventHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	event, err := h.getByIDUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	eventDto := dtoMappers.TimeEventToDto(*event)
	response.Success(c, 200, eventDto)
}

// GetAll godoc
// @Summary Get all time events
// @Description Returns a list of all time events with optional filters.
// @Tags TimeEvent
// @Produce json
// @Security BearerAuth
// @Param eventType query models.Actions false "Event type"
// @Param status query models.TimeEventStatus false "Event status"
// @Param startDateFrom query string false "Start date from. Format: 2026-05-09T00:00:00+05:00"
// @Param startDateTo query string false "Start date to. Format: 2026-05-10T00:00:00+05:00"
// @Param endDateFrom query string false "End date from. Format: 2026-05-09T00:00:00+05:00"
// @Param endDateTo query string false "End date to. Format: 2026-05-10T00:00:00+05:00"
// @Success 200 {array} dto.TimeEvent "List of time events"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/ [get]
func (h *TimeEventHandler) GetAll(c *gin.Context) {
	var req dto.GetTimeEventsQuery

	if err := c.ShouldBindQuery(&req); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	params, err := dtoMappers.TimeEventParamsFromQuery(req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	events, err := h.getAllUC.Execute(c.Request.Context(), params)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	eventsDto := dtoMappers.TimeEventsToDto(events)
	response.Success(c, 200, eventsDto)
}

// FinishTimeEvent godoc
// @Summary FinishTimeEvent
// @Description Changes Time Event Status to ended. Deactivates participants and gives rewards to winners.
// @Tags TimeEvent
// @Produce json
// @Security BearerAuth
// @Param id path int true "Time event ID"
// @Success 200 "finished successfully"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /timeEvent/finish/{id} [post]
func (h *TimeEventHandler) FinishTimeEvent(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	err = h.finishTimeEventUC.Execute(c.Request.Context(), *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 200, "finished successfully")
}
