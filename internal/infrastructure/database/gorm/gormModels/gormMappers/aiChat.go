package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func AIChatToGormModel(chat models.AIChat) gormModels.AIChat {
	return gormModels.AIChat{
		Name:     chat.Name,
		UserID:   chat.UserID,
		Messages: AIChatMessagesToGormModel(chat.Messages),
	}
}

func AIChatsToGormModel(chats []models.AIChat) []gormModels.AIChat {
	if chats == nil {
		return []gormModels.AIChat{}
	}

	result := make([]gormModels.AIChat, 0, len(chats))

	for _, chat := range chats {
		result = append(result, AIChatToGormModel(chat))
	}

	return result
}

func AIChatMessageToGormModel(message models.AiChatMessage) gormModels.AIChatMessage {
	return gormModels.AIChatMessage{
		ChatID:     message.ChatID,
		Message:    message.Message,
		SenderType: string(message.SenderType),
		UserID:     message.UserID,
	}
}

func AIChatMessagesToGormModel(messages []models.AiChatMessage) []gormModels.AIChatMessage {
	if messages == nil {
		return []gormModels.AIChatMessage{}
	}

	result := make([]gormModels.AIChatMessage, 0, len(messages))

	for _, message := range messages {
		result = append(result, AIChatMessageToGormModel(message))
	}

	return result
}

func GormAIChatToDomainModel(chat gormModels.AIChat) models.AIChat {
	return models.AIChat{
		ID:        chat.ID,
		Name:      chat.Name,
		UserID:    chat.UserID,
		Messages:  GormAIChatMessagesToDomainModel(chat.Messages),
		CreatedAt: chat.CreatedAt,
		UpdatedAt: chat.UpdatedAt,
	}
}

func GormAIChatsToDomainModel(chats []gormModels.AIChat) []models.AIChat {
	if chats == nil {
		return []models.AIChat{}
	}

	result := make([]models.AIChat, 0, len(chats))

	for _, chat := range chats {
		result = append(result, GormAIChatToDomainModel(chat))
	}

	return result
}

func GormAIChatMessageToDomainModel(message gormModels.AIChatMessage) models.AiChatMessage {
	return models.AiChatMessage{
		ID:         message.ID,
		ChatID:     message.ChatID,
		Message:    message.Message,
		SenderType: models.SenderType(message.SenderType),
		UserID:     message.UserID,
		User:       GormUserPtrToDomainModel(message.User),
		CreatedAt:  message.CreatedAt,
	}
}

func GormAIChatMessagesToDomainModel(messages []gormModels.AIChatMessage) []models.AiChatMessage {
	if messages == nil {
		return []models.AiChatMessage{}
	}

	result := make([]models.AiChatMessage, 0, len(messages))

	for _, message := range messages {
		result = append(result, GormAIChatMessageToDomainModel(message))
	}

	return result
}
func GormUserPtrToDomainModel(user *gormModels.User) *models.User {
	if user == nil {
		return nil
	}

	domainUser := GormUserToDomain(*user)

	return &domainUser
}
