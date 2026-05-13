package aiChat

import (
	"DaraTilBackendV2/internal/application/usecases/aiChatUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"DaraTilBackendV2/internal/presentation/http/utils"

	"github.com/gin-gonic/gin"
)

type AiChatHandler struct {
	createUC      *aiChatUC.CreateUC
	getAllUC      *aiChatUC.GetAllUC
	getByIDUC     *aiChatUC.GetByIDUC
	updateUC      *aiChatUC.UpdateUC
	deleteUC      *aiChatUC.DeleteUC
	getMessagesUC *aiChatUC.GetMessagesUC
}

func NewAiChatHandler(
	createUC *aiChatUC.CreateUC,
	getAllUC *aiChatUC.GetAllUC,
	getByIDUC *aiChatUC.GetByIDUC,
	updateUC *aiChatUC.UpdateUC,
	deleteUC *aiChatUC.DeleteUC,
	getMessagesUC *aiChatUC.GetMessagesUC,
) *AiChatHandler {
	return &AiChatHandler{
		createUC:      createUC,
		getAllUC:      getAllUC,
		getByIDUC:     getByIDUC,
		updateUC:      updateUC,
		deleteUC:      deleteUC,
		getMessagesUC: getMessagesUC,
	}
}

// Create godoc
// @Summary Create AI chat
// @Description Create a new AI chat for current authenticated user
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param chatReq body dto.CreateAIChatRequest true "AI chat create request"
// @Success 201 {object} dto.AIChatResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /ai-chat [post]
func (h *AiChatHandler) Create(c *gin.Context) {
	var req dto.CreateAIChatRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	chat, err := h.createUC.Execute(c.Request.Context(), dtoMappers.CreateAIChatRequestToDomainModel(req, *userID))
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	chatDto := dtoMappers.AIChatToResponse(*chat)
	response.Success(c, 201, chatDto)
}

// GetAll godoc
// @Summary Get all AI chats
// @Description Get all AI chats of current authenticated user
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {array} dto.AIChatResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /ai-chat [get]
func (h *AiChatHandler) GetAll(c *gin.Context) {
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	chats, err := h.getAllUC.Execute(c.Request.Context(), *userID)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	chatsDto := dtoMappers.AIChatsToResponse(chats)
	response.Success(c, 200, chatsDto)
}

// GetByID godoc
// @Summary Get AI chat by ID
// @Description Get one AI chat with messages by chat ID. User can access only own chats
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "AI chat ID"
// @Success 200 {object} dto.AIChatResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /ai-chat/{id} [get]
func (h *AiChatHandler) GetByID(c *gin.Context) {
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
	chat, err := h.getByIDUC.Execute(c.Request.Context(), *userID, *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	chatDto := dtoMappers.AIChatToResponse(*chat)
	response.Success(c, 200, chatDto)
}

// Update godoc
// @Summary Update AI chat
// @Description Update AI chat name. User can update only own chats
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param chatReq body dto.UpdateAIChatRequest true "AI chat update request"
// @Success 200 {object} dto.AIChatResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /ai-chat [patch]
func (h *AiChatHandler) Update(c *gin.Context) {
	var req dto.UpdateAIChatRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	if req.Name == "" || req.ID == 0 {
		response.HandleDomainError(c, errs.ErrInvalidInput)
		return
	}
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		response.HandleDomainError(c, errs.ErrUnauthorized)
		return
	}
	chat, err := h.updateUC.Execute(c.Request.Context(), *userID, req.ID, req.Name)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	chatDto := dtoMappers.AIChatToResponse(*chat)
	response.Success(c, 200, chatDto)
}

// Delete godoc
// @Summary Delete AI chat
// @Description Delete AI chat by ID. User can delete only own chats
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "AI chat ID"
// @Success 204 {object} string
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /ai-chat/{id} [delete]
func (h *AiChatHandler) Delete(c *gin.Context) {
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
	err = h.deleteUC.Execute(c.Request.Context(), *userID, *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	response.Success(c, 204, "deleted successfully")
}

// GetMessages godoc
// @Summary Get AI chat messages
// @Description Get all messages of one AI chat. User can access only own chat messages
// @Tags AI Chat
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "AI chat ID"
// @Success 200 {array} dto.AIChatMessageResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /ai-chat/{id}/messages [get]
func (h *AiChatHandler) GetMessages(c *gin.Context) {
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
	messages, err := h.getMessagesUC.Execute(c.Request.Context(), *userID, *id)
	if err != nil {
		response.HandleDomainError(c, err)
		return
	}
	messagesDto := dtoMappers.AIChatMessagesToResponse(messages)
	response.Success(c, 200, messagesDto)
}
