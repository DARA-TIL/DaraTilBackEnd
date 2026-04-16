package dto

import "DaraTilBackendV2/internal/domain/models"

type Word struct {
	ID                         uint                       `json:"id"`
	OriginalWord               string                     `json:"originalWord"`
	Context                    string                     `json:"context"`
	WordTranslations           map[models.Language]string `json:"wordTranslations"`
	WordExplainingTranslations map[models.Language]string `json:"wordExplainingTranslations"`
}
type WordCreate struct {
	OriginalWord               string                     `json:"originalWord"`
	Context                    string                     `json:"context"`
	WordTranslations           map[models.Language]string `json:"wordTranslations"`
	WordExplainingTranslations map[models.Language]string `json:"wordExplainingTranslations"`
}
