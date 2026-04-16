package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type WordExplainer interface {
	WordExplain(ctx context.Context, word models.WordRequest) (*models.WordExplainResult, error)
}
