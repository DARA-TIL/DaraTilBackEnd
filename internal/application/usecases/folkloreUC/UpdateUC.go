package folkloreUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
	"fmt"

	"go.uber.org/zap"
)

type UpdateUC struct {
	repo       repo.FolkloreRepo
	translator repo.Translator
}

func NewUpdateUC(repo repo.FolkloreRepo, translator repo.Translator) *UpdateUC {
	return &UpdateUC{
		repo:       repo,
		translator: translator,
	}
}

func (uc *UpdateUC) Execute(ctx context.Context, folkloreID uint, fields models.UpdatableFolkloreFields) (*models.Folklore, error) {
	if fields.Name != nil && fields.Content != nil {
		query := fmt.Sprintf("name" + *fields.Name + "\ncontent:" + *fields.Content)
		translation, err := uc.translator.Translate(context.Background(), query)
		if err != nil {
			logger.Error("error while translating word", zap.Error(err))
			return nil, errs.ErrAi
		}
		kz := models.FolkloreTranslation{
			Language:    "kz",
			Name:        translation.NameKz,
			Content:     translation.ContentKz,
			Explanation: translation.ExplanationKz,
		}
		ru := models.FolkloreTranslation{
			Language:    "ru",
			Name:        translation.NameRu,
			Content:     translation.ContentRu,
			Explanation: translation.ExplanationRu,
		}
		en := models.FolkloreTranslation{
			Language:    "en",
			Name:        translation.NameEn,
			Content:     translation.ContentEn,
			Explanation: translation.ExplanationEn,
		}
		fields.Translations = append(fields.Translations, ru)
		fields.Translations = append(fields.Translations, en)
		fields.Translations = append(fields.Translations, kz)
	}
	return uc.repo.Update(ctx, folkloreID, fields)
}
