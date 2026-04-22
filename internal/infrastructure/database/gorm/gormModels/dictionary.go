package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"

	"gorm.io/gorm"
)

type Word struct {
	gorm.Model
	OriginalWord               string                     `gorm:"not null; uniqueIndex:word_context_idx"`
	Context                    string                     `gorm:"not null; uniqueIndex:word_context_idx"`
	WordTranslations           map[models.Language]string `gorm:"type:jsonb;serializer:json;not null"`
	WordExplainingTranslations map[models.Language]string `gorm:"type:jsonb;serializer:json;not null"`
}

type FavoriteWord struct {
	UserID    uint `gorm:"primaryKey"`
	WordID    uint `gorm:"primaryKey"`
	CreatedAt time.Time

	User User `gorm:"constraint:OnDelete:CASCADE;"`
	Word Word `gorm:"constraint:OnDelete:CASCADE;"`
}
