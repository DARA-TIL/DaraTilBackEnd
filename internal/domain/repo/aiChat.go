package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type AIChatRepo interface {
	Create(ctx context.Context, chat models.AIChat) (*models.AIChat, error)
	Delete(ctx context.Context, userID uint, id uint) error
	Get(ctx context.Context, userID uint, id uint) (*models.AIChat, error)
	GetAll(ctx context.Context, userID uint) ([]models.AIChat, error)
	Update(ctx context.Context, userID uint, id uint, name string) (*models.AIChat, error)
}

type AIChatMessageRepo interface {
	Create(ctx context.Context, message models.AiChatMessage) (*models.AiChatMessage, error)
	Delete(ctx context.Context, userID uint, id uint) error
	GetByChatID(ctx context.Context, userID uint, chatID uint) ([]models.AiChatMessage, error)
	GetRecentByChatID(ctx context.Context, userID uint, chatID uint, limit int) ([]models.AiChatMessage, error)
}
type AIProvider interface {
	GenerateReply(ctx context.Context, messages []models.AiChatMessage) (string, error)
}
