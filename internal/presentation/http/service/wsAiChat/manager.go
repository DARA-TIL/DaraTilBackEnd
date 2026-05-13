package wsAiChat

import (
	"DaraTilBackendV2/internal/application/usecases/aiChatUC"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type WebSocketManager struct {
	ClientList        map[uint]map[string]*AiChatClient //uint: userID; string: connID;
	MaxConnections    uint
	websocketUpgrader *websocket.Upgrader
	sendMessageUC     *aiChatUC.SendMessageUC
	sync.RWMutex
}

func NewWebSocketManager(cfg *config.Config, sendMessageUC *aiChatUC.SendMessageUC) *WebSocketManager {
	webSocketUpgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if cfg.WSSecurity.AllowedOrigins == nil || len(cfg.WSSecurity.AllowedOrigins) == 0 {
				logger.Warn("No Allowed origins, app will not check origins")
				return true
			}
			if origin == "" {
				logger.Error("origin is empty")
				return false
			}
			if slices.Contains(cfg.WSSecurity.AllowedOrigins, origin) {
				return true
			}
			return false
		},
	}
	return &WebSocketManager{
		ClientList:        make(map[uint]map[string]*AiChatClient),
		MaxConnections:    5,
		websocketUpgrader: &webSocketUpgrader,
		sendMessageUC:     sendMessageUC,
	}
}
func (h *WebSocketManager) ServeWS(c *gin.Context) {
	logger.Info("New WS Connection")
	userID, err := middleware.GetCurrentUserID(c)
	if err != nil {
		logger.Error("Get current user id failed", zap.Error(err))
		response.HandleDomainError(c, domErr.ErrUnauthorized)
		return
	}
	h.RLock()
	clientsNum := len(h.ClientList[*userID])
	h.RUnlock()
	if clientsNum >= int(h.MaxConnections) {
		response.Fail(c, http.StatusLocked, "max connections reached")
		logger.Warn("Max connections reached")
		return
	}
	con, err := h.websocketUpgrader.Upgrade(c.Writer, c.Request, nil)

	if err != nil {
		logger.Error("Error upgrading to websocket connection", zap.Error(err))
		return
	}
	client := NewClient(con, h, *userID)
	h.AddClient(client)

	go client.WriteMessages()
	go client.ReadMessages()
}

func (h *WebSocketManager) AddClient(client *AiChatClient) {
	h.Lock()
	defer h.Unlock()
	if _, ok := h.ClientList[client.userID]; !ok {
		h.ClientList[client.userID] = make(map[string]*AiChatClient)
	}

	h.ClientList[client.userID][client.connID] = client
}
func (h *WebSocketManager) RemoveClient(client *AiChatClient) {
	h.Lock()
	defer h.Unlock()
	if _, ok := h.ClientList[client.userID]; ok {
		delete(h.ClientList[client.userID], client.connID)
		if len(h.ClientList[client.userID]) == 0 {
			delete(h.ClientList, client.userID)
		}
	}
}

func (h *WebSocketManager) DisconnectClients(clients []*AiChatClient) {
	for _, client := range clients {
		client.Close()
	}
}

func (h *WebSocketManager) HandleSendMessage(req dto.SendAiChatMessageRequest, c *AiChatClient) {
	if (req.ChatID != nil && *req.ChatID == 0) || strings.TrimSpace(req.Message) == "" {
		c.SendError(errors.New("invalid request"))
		return
	}

	chat, err := h.sendMessageUC.CreateChat(c.ctx, c.userID, req.ChatID, req.Message)
	if err != nil {
		c.SendError(err)
		return
	}
	message, err := h.sendMessageUC.CreateUserMessage(c.ctx, c.userID, chat.ID, req.Message)
	if err != nil {
		c.SendError(err)
		return
	}
	chatPayload, err := json.Marshal(chat)
	if err != nil {
		c.SendError(err)
		return
	}
	newChatMessage := dto.AiChatEvent{
		Type:    models.EventUserMessageSaved,
		Payload: chatPayload,
	}
	h.SendToClient(c, newChatMessage)
	h.SendToClient(c, NewAiChatStatusEvent(models.EventAssistantTyping, chat.ID))
	res, err := h.sendMessageUC.GenerateAiAnswer(c.ctx, c.userID, chat, message)
	if err != nil {
		h.SendToClient(c, NewAiChatStatusEvent(models.EventAssistantTypingEnded, chat.ID))
		c.SendError(domErr.ErrAi)
		return
	}
	resDto := dtoMappers.SendMessageResultToResponse(res)
	payload, _ := json.Marshal(resDto)
	resp := dto.AiChatEvent{
		Type:    models.EventSendMessage,
		Payload: payload,
	}
	h.SendToClient(c, resp)
}
func (h *WebSocketManager) SendToClient(c *AiChatClient, mes dto.AiChatEvent) {
	select {
	case c.egress <- mes:
	default:
		logger.Warn("client egress is full, closing connection",
			zap.String("conn_id", c.connID),
		)
		c.Close()
	}
}

type AiChatStatusPayload struct {
	ChatID uint `json:"chatId"`
}

func NewAiChatStatusEvent(eventType models.AiChatEventTypes, chatID uint) dto.AiChatEvent {
	payload, _ := json.Marshal(AiChatStatusPayload{
		ChatID: chatID,
	})

	return dto.AiChatEvent{
		Type:    eventType,
		Payload: payload,
	}
}
