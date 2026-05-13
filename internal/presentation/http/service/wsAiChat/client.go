package wsAiChat

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

type AiChatClient struct {
	conn    *websocket.Conn
	manager *WebSocketManager
	userID  uint
	connID  string
	egress  chan dto.AiChatEvent
	once    sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewClient(conn *websocket.Conn, handler *WebSocketManager, userID uint) *AiChatClient {
	ctx, cancel := context.WithCancel(context.Background())

	return &AiChatClient{
		conn:    conn,
		manager: handler,
		userID:  userID,
		connID:  uuid.NewString(),
		egress:  make(chan dto.AiChatEvent, 16),
		ctx:     ctx,
		cancel:  cancel,
	}
}
func (c *AiChatClient) Close() {
	c.once.Do(func() {
		c.cancel()
		c.manager.RemoveClient(c)
		_ = c.conn.Close()
	})
}
func (c *AiChatClient) WriteMessages() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()
	for {
		select {
		case message, ok := <-c.egress:
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.conn.WriteJSON(message)
			if err != nil {
				logger.Error("connection closed", zap.Error(err))
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))

			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				logger.Error("ping error", zap.Error(err))
				return
			}
		}
	}
}

func (c *AiChatClient) ReadMessages() {
	defer func() {
		c.Close()
	}()
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))

	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		var req dto.SendAiChatMessageRequest
		err := c.conn.ReadJSON(&req)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Error("connection closed", zap.Error(err))
			}
			c.SendError(err)
			return
		}
		c.manager.HandleSendMessage(req, c)
	}
}
func (c *AiChatClient) SendError(err error) {
	payload, _ := json.Marshal(dto.ErrorPayload{
		Message: err.Error(),
	})

	c.manager.SendToClient(c, dto.AiChatEvent{
		Type:    models.EventError,
		Payload: payload,
	})
}
