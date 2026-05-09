package notification

import (
	"DaraTilBackendV2/internal/application/usecases/notificationUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type NotificationHandler struct {
	createUC  *notificationUC.CreateUC
	updateUC  *notificationUC.UpdateUC
	getAllUC  *notificationUC.GetAllUC
	getByIDUC *notificationUC.GetByIDUC
	deleteUC  *notificationUC.DeleteUC
}

func NewNotificationHandler(createUC *notificationUC.CreateUC,
	updateUC *notificationUC.UpdateUC,
	getAllUC *notificationUC.GetAllUC,
	getByIDUC *notificationUC.GetByIDUC,
	deleteUC *notificationUC.DeleteUC) *NotificationHandler {
	return &NotificationHandler{
		createUC:  createUC,
		updateUC:  updateUC,
		getAllUC:  getAllUC,
		getByIDUC: getByIDUC,
		deleteUC:  deleteUC,
	}
}

// Create godoc
// @Summary Create notification
// @Description Creates a new notification. Admin access required.
// @Tags Notification
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.CreateNotificationRequest true "Notification create payload"
// @Success 201 {object} dto.Notification "Created notification"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/ [post]
func (h *NotificationHandler) Create(c *gin.Context) {
	var req dto.CreateNotificationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	notification := dtoMappers.NotificationFromCreateRequest(req)

	createdNotification, err := h.createUC.Execute(c.Request.Context(), notification)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	notificationDto := dtoMappers.NotificationToDto(*createdNotification)
	response.Success(c, 201, notificationDto)
}

// Update godoc
// @Summary Update notification
// @Description Updates notification fields. Partial update via nullable fields. Admin access required.
// @Tags Notification
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.UpdateNotificationRequest true "Notification update payload"
// @Success 200 {object} dto.Notification "Updated notification"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/ [patch]
func (h *NotificationHandler) Update(c *gin.Context) {
	var req dto.UpdateNotificationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	if req.ID == 0 {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	notificationUpdate := dtoMappers.NotificationUpdateParamsFromRequest(req)

	updatedNotification, err := h.updateUC.Execute(c.Request.Context(), notificationUpdate)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	notificationDto := dtoMappers.NotificationToDto(*updatedNotification)
	response.Success(c, 200, notificationDto)
}

// GetAll godoc
// @Summary Get all notifications
// @Description Returns notifications with optional filters.
// @Tags Notification
// @Produce json
// @Security BearerAuth
// @Param type query models.NotificationType false "Notification type"
// @Param scope query models.NotificationScope false "Notification scope"
// @Param notSeen query bool false "Only unread notifications"
// @Param limit query int false "Limit"
// @Success 200 {array} dto.Notification "List of notifications"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/ [get]
func (h *NotificationHandler) GetAll(c *gin.Context) {
	var req dto.GetNotificationsQuery

	if err := c.ShouldBindQuery(&req); err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	params := dtoMappers.NotificationParamsFromQuery(req, *userID)

	notifications, err := h.getAllUC.Execute(c.Request.Context(), params)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	notificationsDto := dtoMappers.NotificationsToDto(notifications)
	response.Success(c, 200, notificationsDto)
}

// GetByID godoc
// @Summary Get notification by ID
// @Description Returns a notification by ID.
// @Tags Notification
// @Produce json
// @Security BearerAuth
// @Param id path int true "Notification ID"
// @Success 200 {object} dto.Notification "Notification"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/{id} [get]
func (h *NotificationHandler) GetByID(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}

	notification, err := h.getByIDUC.Execute(c.Request.Context(), *id, *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}

	notificationDto := dtoMappers.NotificationToDto(*notification)
	response.Success(c, 200, notificationDto)
}

// Delete godoc
// @Summary Delete notification
// @Description Deletes a notification by ID. Admin access required.
// @Tags Notification
// @Produce json
// @Security BearerAuth
// @Param id path int true "Notification ID"
// @Success 204 "No Content"
// @Failure 400 {object} map[string]interface{} "Bad request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Forbidden"
// @Failure 404 {object} map[string]interface{} "Not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /notifications/{id} [delete]
func (h *NotificationHandler) Delete(c *gin.Context) {
	id, err := utils.GetIdFromParams(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}

	if err := h.deleteUC.Execute(c.Request.Context(), *id); err != nil {
		response.HandleDomainError(c, err)
		return
	}

	response.Success(c, 204, "deleted successfully")
}
