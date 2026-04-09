package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type WordExplainer interface {
	WordExplain(ctx context.Context, word models.WordExplain) (*models.WordExplainResult, error)
}
