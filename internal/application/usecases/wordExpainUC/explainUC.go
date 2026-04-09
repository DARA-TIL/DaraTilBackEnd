package wordExpainUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type WordExplainUC struct {
	explainer repo.WordExplainer
}

func NewWordExplainUC(explainer repo.WordExplainer) *WordExplainUC {
	return &WordExplainUC{explainer: explainer}
}

func (w *WordExplainUC) Explain(ctx context.Context, word models.WordExplain) (*models.WordExplainResult, error) {
	res, err := w.explainer.WordExplain(ctx, word)
	if err != nil {
		logger.Error("error while explaining word", zap.Error(err))
		return nil, errs.ErrInternal
	}
	return res, nil
}
