package dictionaryUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"
)

type UpdateUC struct {
	repo repo.DictionaryRepo
}

func NewUpdateUC(repo repo.DictionaryRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, word models.Word) error {
	if word.ID == 0 {
		logger.Error("wrong id for word update")
		return errs.ErrInvalidInput
	}
	return uc.repo.Update(ctx, word)
}
