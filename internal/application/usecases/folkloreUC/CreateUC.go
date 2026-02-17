package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
	"fmt"
)

type CreateUC struct {
	repo       repo.FolkloreRepo
	translator repo.Translator
}

func NewCreateUC(repo repo.FolkloreRepo, tr repo.Translator) *CreateUC {
	return &CreateUC{
		repo:       repo,
		translator: tr,
	}
}

func (uc *CreateUC) Execute(ctx context.Context, folklore models.Folklore) (*models.Folklore, error) {
	query := fmt.Sprintf("name" + folklore.Name + "\ncontent:" + folklore.Content)
	translation, err := uc.translator.Translate(context.Background(), query)
	if err != nil {
		return nil, err
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
	folklore.Translations = append(folklore.Translations, ru)
	folklore.Translations = append(folklore.Translations, en)
	folklore.Translations = append(folklore.Translations, kz)
	return uc.repo.Create(ctx, folklore)
}
