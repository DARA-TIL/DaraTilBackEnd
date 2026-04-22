package utils

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

func ExplainAndCreateWord(ctx context.Context, req models.WordRequest, e repo.WordExplainer, d repo.DictionaryRepo) (*models.Word, error) {
	res, err := e.WordExplain(ctx, req)
	if err != nil {
		logger.Error("error while explaining word", zap.Error(err))
		return nil, errs.ErrAi
	}
	newWord := models.Word{
		OriginalWord:               req.Word,
		Context:                    req.Block,
		WordTranslations:           res.WordTranslations,
		WordExplainingTranslations: res.WordExplainingTranslations,
	}
	w, err := d.Create(ctx, newWord)
	if err != nil {
		logger.Error("error while creating req", zap.Error(err))
	}
	return w, nil
}
