package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
)

func WordExplainToDomain(we dto.WordExplain) models.WordExplain {
	return models.WordExplain{
		Word:  we.Word,
		Block: we.Block,
		Lang:  we.Lang,
	}
}
func WordExplainResultToDto(wer models.WordExplainResult) dto.WordExplainResult {
	return dto.WordExplainResult{
		Result:  wer.Result,
		Context: wer.Context,
	}
}
