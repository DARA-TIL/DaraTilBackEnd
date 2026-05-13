package models

import "time"

type AIChat struct {
	ID        uint
	Name      string
	UserID    uint
	Messages  []AiChatMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}
type AiChatMessage struct {
	ID         uint
	ChatID     uint
	Message    string
	SenderType SenderType
	UserID     *uint
	User       *User
	CreatedAt  time.Time
}

type SenderType string

const (
	SenderTypeUser      SenderType = "user"
	SenderTypeAssistant SenderType = "assistant"
	SenderTypeSystem    SenderType = "system"
)
