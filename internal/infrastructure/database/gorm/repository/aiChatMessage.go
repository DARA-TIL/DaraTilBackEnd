package repository

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/errhandlers"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels/gormMappers"
	"context"

	"gorm.io/gorm"
)

type AIChatMessageRepository struct {
	db *gorm.DB
}

func NewAIChatMessageRepository(db *gorm.DB) *AIChatMessageRepository {
	return &AIChatMessageRepository{db: db}
}

func (r *AIChatMessageRepository) Create(
	ctx context.Context,
	message models.AiChatMessage,
) (*models.AiChatMessage, error) {
	if message.ChatID == 0 || message.Message == "" || message.SenderType == "" {
		return nil, errs.ErrInvalidInput
	}

	if message.SenderType == "user" && message.UserID == nil {
		return nil, errs.ErrInvalidInput
	}

	gormMessage := gormMappers.AIChatMessageToGormModel(message)

	err := r.db.WithContext(ctx).
		Create(&gormMessage).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	createdMessage := gormMappers.GormAIChatMessageToDomainModel(gormMessage)
	return &createdMessage, nil
}

func (r *AIChatMessageRepository) GetByChatID(
	ctx context.Context,
	userID uint,
	chatID uint,
) ([]models.AiChatMessage, error) {
	if userID == 0 || chatID == 0 {
		return nil, errs.ErrInvalidInput
	}

	var gormMessages []gormModels.AIChatMessage

	err := r.db.WithContext(ctx).
		Model(&gormModels.AIChatMessage{}).
		Joins("JOIN ai_chats ON ai_chats.id = ai_chat_messages.chat_id").
		Where("ai_chat_messages.chat_id = ? AND ai_chats.user_id = ?", chatID, userID).
		Order("ai_chat_messages.created_at ASC").
		Find(&gormMessages).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	messages := gormMappers.GormAIChatMessagesToDomainModel(gormMessages)
	return messages, nil
}

func (r *AIChatMessageRepository) Delete(ctx context.Context, userID uint, id uint) error {
	if userID == 0 || id == 0 {
		return errs.ErrInvalidInput
	}

	res := r.db.WithContext(ctx).
		Model(&gormModels.AIChatMessage{}).
		Joins("JOIN ai_chats ON ai_chats.id = ai_chat_messages.chat_id").
		Where("ai_chat_messages.id = ? AND ai_chats.user_id = ?", id, userID).
		Delete(&gormModels.AIChatMessage{})

	if res.Error != nil {
		return errhandlers.DBErrHandler(res.Error)
	}

	if res.RowsAffected == 0 {
		return errs.ErrNotFound
	}

	return nil
}
