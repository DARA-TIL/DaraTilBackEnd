package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetWordUC struct {
	repo repo.DictionaryRepo
}

func NewGetWordUC(repo repo.DictionaryRepo) *GetWordUC {
	return &GetWordUC{repo: repo}
}

func (uc *GetWordUC) Execute(ctx context.Context, word string) ([]models.Word, error) {
	return uc.repo.GetWord(ctx, word)
}
