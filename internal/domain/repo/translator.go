package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type Translator interface {
	Translate(ctx context.Context, query string) (*models.TranslationObj, error)
}
