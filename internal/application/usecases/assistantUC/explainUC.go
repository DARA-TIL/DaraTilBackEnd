package assistantUC

import (
	"DaraTilBackendV2/internal/application/services"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type WordExplainUC struct {
	explainer repo.WordExplainer
	publisher services.Publisher
}

func NewWordExplainUC(explainer repo.WordExplainer, publisher services.Publisher) *WordExplainUC {
	return &WordExplainUC{
		explainer: explainer,
		publisher: publisher,
	}
}

func (w *WordExplainUC) Explain(ctx context.Context, word models.WordExplain, userID uint) (*models.WordExplainResult, error) {
	res, err := w.explainer.WordExplain(ctx, word)
	if err != nil {
		logger.Error("error while explaining word", zap.Error(err))
		return nil, errs.ErrInternal
	}
	w.publisher.Publish(ctx, services.Event{
		Action: models.Word_Learned,
		UserID: userID,
	})
	return res, nil
}
