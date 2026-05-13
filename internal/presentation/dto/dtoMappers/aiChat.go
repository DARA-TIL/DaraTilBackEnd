package dtoMappers

import (
	"DaraTilBackendV2/internal/application/usecases/aiChatUC"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func CreateAIChatRequestToDomainModel(req dto.CreateAIChatRequest, userID uint) models.AIChat {
	return models.AIChat{
		Name:   req.Name,
		UserID: userID,
	}
}

func AIChatToResponse(chat models.AIChat) dto.AIChatResponse {
	messages := AIChatMessagesToResponse(chat.Messages)

	var lastMessage *dto.AIChatMessageResponse

	if len(chat.Messages) > 0 {
		mapped := AIChatMessageToResponse(chat.Messages[0])
		lastMessage = &mapped
	}

	return dto.AIChatResponse{
		ID:          chat.ID,
		Name:        chat.Name,
		UserID:      chat.UserID,
		Messages:    messages,
		LastMessage: lastMessage,
		CreatedAt:   chat.CreatedAt,
		UpdatedAt:   chat.UpdatedAt,
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

func AIChatMessageToResponse(message models.AiChatMessage) dto.AIChatMessageResponse {
	return dto.AIChatMessageResponse{
		ID:         message.ID,
		ChatID:     message.ChatID,
		Message:    message.Message,
		SenderType: message.SenderType,
		UserID:     message.UserID,
		CreatedAt:  message.CreatedAt,
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
func SendMessageResultToResponse(
	result *aiChatUC.SendMessageResult,
) *dto.SendMessageResponse {
	if result == nil {
		return nil
	}

	return &dto.SendMessageResponse{
		Chat:        AIChatToShortResponse(result.Chat),
		UserMessage: AIChatMessageToResponse(*result.UserMessage),
		AIMessage:   AIChatMessageToResponse(*result.AIMessage),
	}
}

func AIChatToShortResponse(chat *models.AIChat) dto.AIChatShortResponse {
	if chat == nil {
		return dto.AIChatShortResponse{}
	}

	return dto.AIChatShortResponse{
		ID:     chat.ID,
		Name:   chat.Name,
		UserID: chat.UserID,
	}
}
