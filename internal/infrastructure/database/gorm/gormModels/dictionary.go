package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"

	"gorm.io/gorm"
)

type Word struct {
	gorm.Model
	OriginalWord               string                     `gorm:"not null; uniqueIndex:word_context_idx"`
	Context                    string                     `gorm:"not null; uniqueIndex:word_context_idx"`
	WordTranslations           map[models.Language]string `gorm:"type:jsonb;serializer:json;not null"`
	WordExplainingTranslations map[models.Language]string `gorm:"type:jsonb;serializer:json;not null"`
}
