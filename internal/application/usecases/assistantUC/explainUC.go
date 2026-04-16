package assistantUC

import (
	"DaraTilBackendV2/internal/application/services"
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
			return nil, dbErr
		}
		res, err := w.explainer.WordExplain(ctx, req)
		if err != nil {
			logger.Error("error while explaining req", zap.Error(err))
			return nil, errs.ErrInternal
		}
		newWord := models.Word{
			OriginalWord:               req.Word,
			Context:                    req.Block,
			WordTranslations:           res.WordTranslations,
			WordExplainingTranslations: res.WordExplainingTranslations,
		}
		err = w.dictionaryRepo.Create(ctx, newWord)
		if err != nil {
			logger.Error("error while creating req", zap.Error(err))
		}
		w.publisher.Publish(ctx, services.Event{
			Action: models.Word_Learned,
			UserID: userID,
		})
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
