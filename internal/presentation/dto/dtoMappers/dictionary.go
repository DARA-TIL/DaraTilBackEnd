package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func WordToDTOModel(word models.Word) dto.Word {
	return dto.Word{
		ID:                         word.ID,
		OriginalWord:               word.OriginalWord,
		Context:                    word.Context,
		WordTranslations:           WordTranslationsToDTOModel(word.WordTranslations),
		WordExplainingTranslations: WordExplainingTranslationsToDTOModel(word.WordExplainingTranslations),
	}
}

func DTOWordToDomainModel(word dto.Word) models.Word {
	return models.Word{
		ID:                         word.ID,
		OriginalWord:               word.Context,
		Context:                    word.Context,
		WordTranslations:           DTOWordTranslationsToDomainModel(word.WordTranslations),
		WordExplainingTranslations: DTOWordExplainingTranslationsToDomainModel(word.WordExplainingTranslations),
	}
}

func WordTranslationsToDTOModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func WordExplainingTranslationsToDTOModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func DTOWordTranslationsToDomainModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func DTOWordExplainingTranslationsToDomainModel(translations map[models.Language]string) map[models.Language]string {
	if translations == nil {
		return map[models.Language]string{}
	}

	result := make(map[models.Language]string, len(translations))
	for lang, value := range translations {
		result[lang] = value
	}
	return result
}

func WordsToDTOModel(words []models.Word) []dto.Word {
	if words == nil {
		return []dto.Word{}
	}

	result := make([]dto.Word, 0, len(words))
	for _, word := range words {
		result = append(result, WordToDTOModel(word))
	}
	return result
}

func DTOWordsToDomainModel(words []dto.Word) []models.Word {
	if words == nil {
		return []models.Word{}
	}

	result := make([]models.Word, 0, len(words))
	for _, word := range words {
		result = append(result, DTOWordToDomainModel(word))
	}
	return result
}
func DTOWordCreateToDomainModel(word dto.WordCreate) models.Word {
	return models.Word{
		OriginalWord:               word.OriginalWord,
		Context:                    word.Context,
		WordTranslations:           DTOWordTranslationsToDomainModel(word.WordTranslations),
		WordExplainingTranslations: DTOWordExplainingTranslationsToDomainModel(word.WordExplainingTranslations),
	}
}
