package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func FolkloreToGormModel(folklore models.Folklore) gormModels.Folklore {
	return gormModels.Folklore{
		Type:         folklore.Type,
		Author:       folklore.Author,
		Region:       folklore.Region,
		Content:      folklore.Content,
		Name:         folklore.Name,
		MediaUrl:     folklore.MediaUrl,
		ImageUrl:     folklore.ImageUrl,
		LikesCount:   folklore.LikesCount,
		Translations: TranslationsToGormModel(folklore.Translations),
	}
}
func TranslationsToGormModel(translations []models.FolkloreTranslation) []gormModels.FolkloreTranslation {
	var translationsGorm []gormModels.FolkloreTranslation
	for _, tr := range translations {
		gormTranslation := gormModels.FolkloreTranslation{
			Language:    tr.Language,
			Name:        tr.Name,
			Content:     tr.Content,
			Explanation: tr.Explanation,
		}
		translationsGorm = append(translationsGorm, gormTranslation)
	}
	return translationsGorm
}

func GormFolkloreToDomainModel(folklore gormModels.Folklore) models.Folklore {
	return models.Folklore{
		ID:           folklore.ID,
		Type:         folklore.Type,
		Author:       folklore.Author,
		Region:       folklore.Region,
		Content:      folklore.Content,
		Name:         folklore.Name,
		MediaUrl:     folklore.MediaUrl,
		ImageUrl:     folklore.ImageUrl,
		LikesCount:   folklore.LikesCount,
		Translations: GormTranslationsToDomainModel(folklore.Translations),
	}
}

func GormTranslationsToDomainModel(translations []gormModels.FolkloreTranslation) []models.FolkloreTranslation {
	var translationsDomain []models.FolkloreTranslation
	for _, tr := range translations {
		domainTranslation := models.FolkloreTranslation{
			ID:          tr.ID,
			FolkloreID:  tr.FolkloreID,
			Language:    tr.Language,
			Name:        tr.Name,
			Content:     tr.Content,
			Explanation: tr.Explanation,
		}
		translationsDomain = append(translationsDomain, domainTranslation)
	}
	return translationsDomain
}
