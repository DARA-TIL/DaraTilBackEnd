package ws

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/dto/dtoMappers"
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

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

type Client struct {
	conn    *websocket.Conn
	handler *WebSocketManager
	userID  uint
	connID  string
	egress  chan models.Notification
	once    sync.Once
}

func NewClient(conn *websocket.Conn, handler *WebSocketManager, userID uint) *Client {
	return &Client{
		conn:    conn,
		handler: handler,
		userID:  userID,
		connID:  uuid.NewString(),
		egress:  make(chan models.Notification, 16),
	}
}

func (c *Client) WriteMessages() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()
	for {
		select {
		case message := <-c.egress:

			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			dtoNotification := dtoMappers.NotificationToDto(message)
			err := c.conn.WriteJSON(dtoNotification)
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

func (c *Client) ReadMessages() {
	defer func() {
		c.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))

	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logger.Error("connection closed", zap.Error(err))
			}
			return
		}
	}
}

func (c *Client) Close() {
	c.once.Do(func() {
		c.handler.RemoveClient(c)
		_ = c.conn.Close()
	})
}
