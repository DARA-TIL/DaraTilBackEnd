package wsNotification

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/response"
	"context"
	"net/http"
	"slices"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type NotificationWebSocketManager struct {
	ClientList        map[uint]map[string]*NotificationClient //uint: userID; string: connID;
	MaxConnections    uint
	websocketUpgrader *websocket.Upgrader
	sync.RWMutex
}

func NewWebSocketManager(cfg *config.Config) *NotificationWebSocketManager {
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
	return &NotificationWebSocketManager{
		ClientList:        make(map[uint]map[string]*NotificationClient),
		MaxConnections:    5,
		websocketUpgrader: &webSocketUpgrader,
	}
}

func (h *NotificationWebSocketManager) ServeWS(c *gin.Context) {
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

func (h *NotificationWebSocketManager) AddClient(client *NotificationClient) {
	h.Lock()
	defer h.Unlock()
	if _, ok := h.ClientList[client.userID]; !ok {
		h.ClientList[client.userID] = make(map[string]*NotificationClient)
	}

	h.ClientList[client.userID][client.connID] = client
}
func (h *NotificationWebSocketManager) RemoveClient(client *NotificationClient) {
	h.Lock()
	defer h.Unlock()
	if _, ok := h.ClientList[client.userID]; ok {
		delete(h.ClientList[client.userID], client.connID)
		if len(h.ClientList[client.userID]) == 0 {
			delete(h.ClientList, client.userID)
		}
	}
}

func (h *NotificationWebSocketManager) Handle(ctx context.Context, notif models.Notification) {
	h.RLock()
	if notif.UserID == nil && notif.Scope == models.NotificationScopeGlobal {
		h.SendToAllClients(notif)
		return
	}
	clientCons, ok := h.ClientList[*notif.UserID] //ClientConnections
	if !ok {
		h.RUnlock()
		logger.Error("user is not connected", zap.Uint("user_id", *notif.UserID))
		return
	}
	clients := make([]*NotificationClient, 0, len(clientCons))
	for _, c := range clientCons {
		clients = append(clients, c)
	}
	h.RUnlock()
	if notif.Type == models.NotifLogOut {
		h.DisconnectClients(clients)
		return
	}

	h.SendToClients(clients, notif)

}

func (h *NotificationWebSocketManager) SendToClients(clients []*NotificationClient, notif models.Notification) {
	for _, c := range clients {
		select {
		case c.egress <- notif:
		default:
			logger.Warn("client egress is full",
				zap.Uint("user_id", *notif.UserID),
				zap.String("conn_id", c.connID),
			)
		}
	}
}
func (h *NotificationWebSocketManager) DisconnectClients(clients []*NotificationClient) {
	for _, client := range clients {
		client.Close()
	}
}

func (h *NotificationWebSocketManager) SendToAllClients(notif models.Notification) {
	for _, clients := range h.ClientList {
		for _, client := range clients {
			select {
			case client.egress <- notif:
			default:
				logger.Warn("client egress is full",
					zap.Uint("user_id", *notif.UserID),
					zap.String("conn_id", client.connID),
				)
			}
		}
	}
}
