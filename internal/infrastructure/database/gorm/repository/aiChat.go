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

type AIChatRepository struct {
	db *gorm.DB
}

func NewAIChatRepository(db *gorm.DB) *AIChatRepository {
	return &AIChatRepository{db: db}
}

func (r *AIChatRepository) Create(ctx context.Context, chat models.AIChat) (*models.AIChat, error) {
	if chat.UserID == 0 {
		return nil, errs.ErrInvalidInput
	}

	gormChat := gormMappers.AIChatToGormModel(chat)

	err := r.db.WithContext(ctx).
		Create(&gormChat).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	createdChat := gormMappers.GormAIChatToDomainModel(gormChat)
	return &createdChat, nil
}

func (r *AIChatRepository) Get(ctx context.Context, userID uint, id uint) (*models.AIChat, error) {
	if userID == 0 || id == 0 {
		return nil, errs.ErrInvalidInput
	}

	var gormChat gormModels.AIChat

	err := r.db.WithContext(ctx).
		Preload("Messages").
		Where("id = ? AND user_id = ?", id, userID).
		First(&gormChat).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	chat := gormMappers.GormAIChatToDomainModel(gormChat)
	return &chat, nil
}

func (r *AIChatRepository) GetAll(ctx context.Context, userID uint) ([]models.AIChat, error) {
	if userID == 0 {
		return nil, errs.ErrInvalidInput
	}

	var gormChats []gormModels.AIChat

	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC, id DESC").
		Find(&gormChats).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	if len(gormChats) == 0 {
		return []models.AIChat{}, nil
	}

	chatIDs := make([]uint, 0, len(gormChats))
	for _, chat := range gormChats {
		chatIDs = append(chatIDs, chat.ID)
	}

	var lastMessages []gormModels.AIChatMessage

	err = r.db.WithContext(ctx).
		Raw(`
			SELECT DISTINCT ON (chat_id) *
			FROM ai_chat_messages
			WHERE chat_id IN ?
			  AND deleted_at IS NULL
			ORDER BY chat_id, created_at DESC, id DESC
		`, chatIDs).
		Scan(&lastMessages).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	lastMessageByChatID := make(map[uint]gormModels.AIChatMessage)

	for _, message := range lastMessages {
		lastMessageByChatID[message.ChatID] = message
	}

	for i := range gormChats {
		if message, ok := lastMessageByChatID[gormChats[i].ID]; ok {
			gormChats[i].Messages = []gormModels.AIChatMessage{message}
		}
	}

	chats := gormMappers.GormAIChatsToDomainModel(gormChats)
	return chats, nil
}

func (r *AIChatRepository) Update(ctx context.Context, userID uint, id uint, name string) (*models.AIChat, error) {
	if userID == 0 || id == 0 || name == "" {
		return nil, errs.ErrInvalidInput
	}

	res := r.db.WithContext(ctx).
		Model(&gormModels.AIChat{}).
		Where("id = ? AND user_id = ?", id, userID).
		Update("name", name)

	if res.Error != nil {
		return nil, errhandlers.DBErrHandler(res.Error)
	}

	if res.RowsAffected == 0 {
		return nil, errs.ErrNotFound
	}

	var gormChat gormModels.AIChat

	err := r.db.WithContext(ctx).
		Preload("Messages").
		Where("id = ? AND user_id = ?", id, userID).
		First(&gormChat).
		Error
	if err != nil {
		return nil, errhandlers.DBErrHandler(err)
	}

	chat := gormMappers.GormAIChatToDomainModel(gormChat)
	return &chat, nil
}

func (r *AIChatRepository) Delete(ctx context.Context, userID uint, id uint) error {
	if userID == 0 || id == 0 {
		return errs.ErrInvalidInput
	}

	res := r.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", id, userID).
		Unscoped().
		Delete(&gormModels.AIChat{})

	if res.Error != nil {
		return errhandlers.DBErrHandler(res.Error)
	}

	if res.RowsAffected == 0 {
		return errs.ErrNotFound
	}

	return nil
}
