package assistantUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/application/usecases/subscriptionUC"
	"DaraTilBackendV2/internal/application/utils"
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"errors"

	"go.uber.org/zap"
)

type WordExplainUC struct {
	dictionaryRepo    repo.DictionaryRepo
	explainer         repo.WordExplainer
	publisher         services.Publisher
	checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC
}

func NewWordExplainUC(explainer repo.WordExplainer, publisher services.Publisher, dictionaryRepo repo.DictionaryRepo, checkDailyUsageUC *subscriptionUC.CheckDailyActionLimitUC) *WordExplainUC {
	return &WordExplainUC{
		dictionaryRepo:    dictionaryRepo,
		explainer:         explainer,
		publisher:         publisher,
		checkDailyUsageUC: checkDailyUsageUC,
	}
}

func (uc *WordExplainUC) Explain(ctx context.Context, req models.WordRequest, userID uint) (*models.WordExplainResult, error) {
	err := uc.checkDailyUsageUC.Execute(ctx, userID, "explain")
	if err != nil {
		return nil, err
	}
	existingWord, dbErr := uc.dictionaryRepo.GetExactWord(ctx, req.Word, req.Block)
	if dbErr != nil {
		if !errors.Is(dbErr, errs.ErrNotFound) {
			logger.Error("error getting existing word", zap.String("word", req.Word), zap.Error(dbErr))
			return nil, dbErr
		}
		logger.Info("word not found, getting info from AI")
		word, err := utils.ExplainAndCreateWord(ctx, req, uc.explainer, uc.dictionaryRepo)
		if err != nil {
			return nil, err
		}
		uc.publisher.Publish(ctx, services.Event{
			Action:     models.Word_Learned,
			UserID:     userID,
			EntityID:   word.ID,
			EntityType: "word",
		})
		res := &models.WordExplainResult{
			WordTranslations:           word.WordTranslations,
			WordExplainingTranslations: word.WordExplainingTranslations,
		}
		return res, nil
	}
	uc.publisher.Publish(ctx, services.Event{
		Action: models.Word_Learned,
		UserID: userID,
	})
	res := &models.WordExplainResult{
		WordTranslations:           existingWord.WordTranslations,
		WordExplainingTranslations: existingWord.WordExplainingTranslations,
	}
	return res, nil
}
