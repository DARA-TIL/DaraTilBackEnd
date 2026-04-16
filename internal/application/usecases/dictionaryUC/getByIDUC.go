package dictionaryUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.DictionaryRepo
}

func NewGetByIDUC(repo repo.DictionaryRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}

func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.Word, error) {
	return uc.repo.GetByID(ctx, id)
}
