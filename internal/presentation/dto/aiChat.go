package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"encoding/json"
	"time"
)

type AiChatEvent struct {
	Type    models.AiChatEventTypes `json:"type"`
	Payload json.RawMessage         `json:"payload,omitempty"`
}

type SendMessagePayload struct {
	ChatID  *uint  `json:"chatId,omitempty"`
	Message string `json:"message"`
}

type ErrorPayload struct {
	Message string `json:"message"`
}

type CreateAIChatRequest struct {
	Name string `json:"name" binding:"required"`
}

type UpdateAIChatRequest struct {
	ID   uint   `json:"id" binding:"required"`
	Name string `json:"name" binding:"required"`
}

type AIChatResponse struct {
	ID          uint                    `json:"id"`
	Name        string                  `json:"name"`
	UserID      uint                    `json:"userId"`
	Messages    []AIChatMessageResponse `json:"messages,omitempty"`
	LastMessage *AIChatMessageResponse  `json:"lastMessage,omitempty"`
	CreatedAt   time.Time               `json:"createdAt"`
	UpdatedAt   time.Time               `json:"updatedAt"`
}

type SendAiChatMessageRequest struct {
	ChatID  *uint  `json:"chatId,omitempty"`
	Message string `json:"message" binding:"required"`
}

type AIChatMessageResponse struct {
	ID         uint              `json:"id"`
	ChatID     uint              `json:"chatId"`
	Message    string            `json:"message"`
	SenderType models.SenderType `json:"senderType"`
	UserID     *uint             `json:"userId,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
}
type SendMessageResponse struct {
	Chat        AIChatShortResponse   `json:"chat"`
	UserMessage AIChatMessageResponse `json:"userMessage"`
	AIMessage   AIChatMessageResponse `json:"aiMessage"`
}

type AIChatShortResponse struct {
	ID     uint   `json:"id"`
	Name   string `json:"name"`
	UserID uint   `json:"userId"`
}
