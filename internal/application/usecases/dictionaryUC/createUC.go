package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.DictionaryRepo
}

func NewCreateUC(repo repo.DictionaryRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, word models.Word) error {
	_, err := uc.repo.Create(ctx, word)
	return err
}
