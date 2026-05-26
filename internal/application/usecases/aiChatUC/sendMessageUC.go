package aiChatUC

import (
	"DaraTilBackendV2/internal/application/usecases/subscriptionUC"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"strings"
	"unicode/utf8"
)

const (
	MaxMessageLength = 2000
	HistoryLimit     = 20
)

type SendMessageResult struct {
	Chat        *models.AIChat
	UserMessage *models.AiChatMessage
	AIMessage   *models.AiChatMessage
}

type SendMessageUC struct {
	repo              repo.AIChatRepo
	messageRepo       repo.AIChatMessageRepo
	aiProvider        repo.AIProvider
	checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC
}

func NewSendMessageUC(
	repo repo.AIChatRepo,
	messageRepo repo.AIChatMessageRepo,
	aiProvider repo.AIProvider,
	checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC,
) *SendMessageUC {
	return &SendMessageUC{
		repo:              repo,
		messageRepo:       messageRepo,
		aiProvider:        aiProvider,
		checkDailyUsageUC: checkDailyUsageUC,
	}
}

func (uc *SendMessageUC) CreateChat(ctx context.Context, userID uint, id *uint, text string) (*models.AIChat, error) {
	if userID == 0 {
		return nil, errs.ErrInvalidInput
	}
	if err := uc.checkDailyUsageUC.Execute(ctx, userID, "aiChat"); err != nil {
		return nil, err
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errs.ErrInvalidInput
	}

	if utf8.RuneCountInString(text) > MaxMessageLength {
		return nil, errs.ErrInvalidInput
	}

	return uc.resolve(ctx, userID, id, text)
}
func (uc *SendMessageUC) CreateUserMessage(ctx context.Context, userID uint, id uint, text string) (*models.AiChatMessage, error) {
	return uc.messageRepo.Create(ctx, models.AiChatMessage{
		ChatID:     id,
		Message:    text,
		SenderType: models.SenderTypeUser,
		UserID:     &userID,
	})
}

func (uc *SendMessageUC) GenerateAiAnswer(ctx context.Context, userID uint, chat *models.AIChat, userMessage *models.AiChatMessage) (*SendMessageResult, error) {
	history, err := uc.messageRepo.GetRecentByChatID(ctx, userID, chat.ID, HistoryLimit)
	if err != nil {
		return nil, err
	}

	aiText, err := uc.aiProvider.GenerateReply(ctx, history)
	if err != nil {
		return nil, err
	}

	aiText = strings.TrimSpace(aiText)
	if aiText == "" {
		return nil, errs.ErrInternal
	}

	aiMessage, err := uc.messageRepo.Create(ctx, models.AiChatMessage{
		ChatID:     chat.ID,
		Message:    aiText,
		SenderType: models.SenderTypeAssistant,
		UserID:     nil,
	})
	if err != nil {
		return nil, err
	}

	return &SendMessageResult{
		Chat:        chat,
		UserMessage: userMessage,
		AIMessage:   aiMessage,
	}, nil
}

func (uc *SendMessageUC) resolve(
	ctx context.Context,
	userID uint,
	id *uint,
	text string,
) (*models.AIChat, error) {
	if id == nil {
		return uc.repo.Create(ctx, models.AIChat{
			Name:   makeName(text),
			UserID: userID,
		})
	}

	if *id == 0 {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.Get(ctx, userID, *id)
}

func makeName(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "New Chat"
	}

	const maxRunes = 40

	runes := []rune(text)
	if len(runes) <= maxRunes {
		return text
	}

	return string(runes[:maxRunes]) + "..."
}
