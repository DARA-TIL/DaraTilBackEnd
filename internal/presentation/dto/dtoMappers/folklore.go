package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func DtoFolkloreToDomain(folkloreDTO dto.FolkloreDTO) models.Folklore {
	return models.Folklore{
		ID:           folkloreDTO.ID,
		Type:         folkloreDTO.Type,
		Author:       folkloreDTO.Author,
		Region:       folkloreDTO.Region,
		Content:      folkloreDTO.Content,
		Name:         folkloreDTO.Name,
		MediaUrl:     folkloreDTO.MediaUrl,
		ImageUrl:     folkloreDTO.ImageUrl,
		LikesCount:   folkloreDTO.LikesCount,
		Translations: dtoTranslationToDomain(folkloreDTO.Translations),
	}
}

func dtoTranslationToDomain(translationsDto []dto.FolkloreTranslationDTO) []models.FolkloreTranslation {
	var translations []models.FolkloreTranslation
	for _, t := range translationsDto {
		translations = append(translations, models.FolkloreTranslation{
			ID:          t.ID,
			FolkloreID:  t.FolkloreID,
			Language:    t.Language,
			Name:        t.Name,
			Content:     t.Content,
			Explanation: t.Explanation,
		})
	}
	return translations
}

func FolkloreToDto(folklore models.Folklore) dto.FolkloreDTO {
	return dto.FolkloreDTO{
		ID:           folklore.ID,
		Type:         folklore.Type,
		Author:       folklore.Author,
		Region:       folklore.Region,
		Content:      folklore.Content,
		Name:         folklore.Name,
		MediaUrl:     folklore.MediaUrl,
		ImageUrl:     folklore.ImageUrl,
		LikesCount:   folklore.LikesCount,
		Translations: translationsToDto(folklore.Translations),
	}
}

func translationsToDto(translations []models.FolkloreTranslation) []dto.FolkloreTranslationDTO {
	var translationsDto []dto.FolkloreTranslationDTO
	for _, t := range translations {
		translationsDto = append(translationsDto, dto.FolkloreTranslationDTO{
			ID:          t.ID,
			FolkloreID:  t.FolkloreID,
			Language:    t.Language,
			Name:        t.Name,
			Content:     t.Content,
			Explanation: t.Explanation,
		})
	}
	return translationsDto
}

func DtoUpdatableFolkloreToDomain(upd dto.UpdatableFolkloreFieldsDTO) models.UpdatableFolkloreFields {
	return models.UpdatableFolkloreFields{
		Type:     upd.Type,
		Author:   upd.Author,
		Region:   upd.Region,
		Content:  upd.Content,
		Name:     upd.Name,
		MediaUrl: upd.MediaUrl,
		ImageUrl: upd.ImageUrl,
	}
}
func UpdatableFolkloreToDto(upd models.UpdatableFolkloreFields) dto.UpdatableFolkloreFieldsDTO {
	return dto.UpdatableFolkloreFieldsDTO{
		Type:     upd.Type,
		Author:   upd.Author,
		Region:   upd.Region,
		Content:  upd.Content,
		Name:     upd.Name,
		MediaUrl: upd.MediaUrl,
		ImageUrl: upd.ImageUrl,
	}
}
