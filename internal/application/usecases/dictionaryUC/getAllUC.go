package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.DictionaryRepo
}

func NewGetAllUC(repo repo.DictionaryRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}

func (uc *GetAllUC) Execute(ctx context.Context) ([]models.Word, error) {
	return uc.repo.GetAll(ctx)
}
