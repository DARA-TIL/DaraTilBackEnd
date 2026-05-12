package models

type AIChat struct {
	ID      uint
	Name    string
	UserID  uint
	Message []AiChatMessage
}
type AiChatMessage struct {
	ID         uint
	ChatID     uint
	Message    string
	SenderType string
	UserID     *uint
	User       *User
}
