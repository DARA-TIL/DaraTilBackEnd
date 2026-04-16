package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func WordExplainToDomain(we dto.WordExplain) models.WordRequest {
	return models.WordRequest{
		Word:  we.Word,
		Block: we.Block,
	}
}
func WordExplainResultToDto(wer models.WordExplainResult, lang models.Language) dto.WordExplainResult {
	return dto.WordExplainResult{
		Result:  wer.WordTranslations[lang],
		Context: wer.WordExplainingTranslations[lang],
	}
}
