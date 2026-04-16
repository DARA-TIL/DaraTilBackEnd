package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func WordToGormModel(word models.Word) gormModels.Word {
	return gormModels.Word{
		OriginalWord:               word.OriginalWord,
		Context:                    word.Context,
		WordTranslations:           WordTranslationsToGormModel(word.WordTranslations),
		WordExplainingTranslations: WordExplainingTranslationsToGormModel(word.WordExplainingTranslations),
	}
}

func WordTranslationsToGormModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func WordExplainingTranslationsToGormModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func GormWordToDomainModel(word gormModels.Word) models.Word {
	return models.Word{
		ID:                         word.ID,
		OriginalWord:               word.OriginalWord,
		Context:                    word.Context,
		WordTranslations:           GormWordTranslationsToDomainModel(word.WordTranslations),
		WordExplainingTranslations: GormWordExplainingTranslationsToDomainModel(word.WordExplainingTranslations),
	}
}

func GormWordTranslationsToDomainModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func GormWordExplainingTranslationsToDomainModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}
func WordsToGormModel(words []models.Word) []gormModels.Word {
	result := make([]gormModels.Word, 0, len(words))
	for _, word := range words {
		result = append(result, WordToGormModel(word))
	}
	return result
}

func GormWordsToDomainModel(words []gormModels.Word) []models.Word {
	result := make([]models.Word, 0, len(words))
	for _, word := range words {
		result = append(result, GormWordToDomainModel(word))
	}
	return result
}
