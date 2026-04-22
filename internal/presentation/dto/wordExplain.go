package dto

import "DaraTilBackendV2/internal/domain/models"

type WordExplain struct {
	Word  string          `json:"word"`
	Block string          `json:"block"`
	Lang  models.Language `json:"lang"`
}

type WordExplainResult struct {
	Result  string `json:"result"`
	Context string `json:"context"`
}

type WordTranslationResult struct {
	Result string `json:"result"`
}
