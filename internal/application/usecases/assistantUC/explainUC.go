package assistantUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/helpers"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"errors"

	"go.uber.org/zap"
)

type WordExplainUC struct {
	dictionaryRepo repo.DictionaryRepo
	explainer      repo.WordExplainer
	publisher      services.Publisher
}

func NewWordExplainUC(explainer repo.WordExplainer, publisher services.Publisher, dictionaryRepo repo.DictionaryRepo) *WordExplainUC {
	return &WordExplainUC{
		dictionaryRepo: dictionaryRepo,
		explainer:      explainer,
		publisher:      publisher,
	}
}

func (w *WordExplainUC) Explain(ctx context.Context, req models.WordRequest, userID uint) (*models.WordExplainResult, error) {
	existingWord, dbErr := w.dictionaryRepo.GetExactWord(ctx, req.Word, req.Block)
	if dbErr != nil {
		if !errors.Is(dbErr, errs.ErrNotFound) {
			logger.Error("error getting existing word", zap.String("word", req.Word), zap.Error(dbErr))
			return nil, dbErr
		}
		logger.Info("word not found, getting info from AI")
		word, err := helpers.ExplainAndCreateWord(ctx, userID, req, w.explainer, w.dictionaryRepo)
		if err != nil {
			return nil, err
		}
		w.publisher.Publish(ctx, services.Event{
			Action: models.Word_Learned,
			UserID: userID,
		})
		res := &models.WordExplainResult{
			WordTranslations:           word.WordTranslations,
			WordExplainingTranslations: word.WordExplainingTranslations,
		}
		return res, nil
	}
	w.publisher.Publish(ctx, services.Event{
		Action: models.Word_Learned,
		UserID: userID,
	})
	res := &models.WordExplainResult{
		WordTranslations:           existingWord.WordTranslations,
		WordExplainingTranslations: existingWord.WordExplainingTranslations,
	}
	return res, nil
}
