package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func CreateAIChatRequestToDomainModel(req dto.CreateAIChatRequest, userID uint) models.AIChat {
	return models.AIChat{
		Name:   req.Name,
		UserID: userID,
	}
}

func UpdateAIChatRequestToDomainName(req dto.UpdateAIChatRequest) string {
	return req.Name
}

func AIChatToResponse(chat models.AIChat) dto.AIChatResponse {
	return dto.AIChatResponse{
		ID:       chat.ID,
		Name:     chat.Name,
		UserID:   chat.UserID,
		Messages: AIChatMessagesToResponse(chat.Message),
	}
}

func AIChatsToResponse(chats []models.AIChat) []dto.AIChatResponse {
	if chats == nil {
		return []dto.AIChatResponse{}
	}

	result := make([]dto.AIChatResponse, 0, len(chats))

	for _, chat := range chats {
		result = append(result, AIChatToResponse(chat))
	}

	return result
}

func CreateAIChatMessageRequestToDomainModel(
	req dto.CreateAIChatMessageRequest,
	userID uint,
) models.AiChatMessage {
	return models.AiChatMessage{
		ChatID:     req.ChatID,
		Message:    req.Message,
		SenderType: req.SenderType,
		UserID:     &userID,
	}
}

func CreateAIChatMessageRequestToDomainModelWithChatID(
	req dto.CreateAIChatMessageRequest,
	userID uint,
	chatID uint,
) models.AiChatMessage {
	return models.AiChatMessage{
		ChatID:     chatID,
		Message:    req.Message,
		SenderType: req.SenderType,
		UserID:     &userID,
	}
}

func AIChatMessageToResponse(message models.AiChatMessage) dto.AIChatMessageResponse {
	return dto.AIChatMessageResponse{
		ID:         message.ID,
		ChatID:     message.ChatID,
		Message:    message.Message,
		SenderType: message.SenderType,
		UserID:     message.UserID,
	}
}

func AIChatMessagesToResponse(messages []models.AiChatMessage) []dto.AIChatMessageResponse {
	if messages == nil {
		return []dto.AIChatMessageResponse{}
	}

	result := make([]dto.AIChatMessageResponse, 0, len(messages))

	for _, message := range messages {
		result = append(result, AIChatMessageToResponse(message))
	}

	return result
}
func NewAIMessageDomainModel(chatID uint, message string) models.AiChatMessage {
	return models.AiChatMessage{
		ChatID:     chatID,
		Message:    message,
		SenderType: "ai",
		UserID:     nil,
	}
}
func NewUserMessageDomainModel(chatID uint, userID uint, message string) models.AiChatMessage {
	return models.AiChatMessage{
		ChatID:     chatID,
		Message:    message,
		SenderType: "user",
		UserID:     &userID,
	}
}
