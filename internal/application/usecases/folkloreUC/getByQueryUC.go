package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByQueryUC struct {
	repo repo.FolkloreRepo
}

func NewGetByQueryUC(repo repo.FolkloreRepo) *GetByQueryUC {
	return &GetByQueryUC{repo: repo}
}

func (uc *GetByQueryUC) Execute(ctx context.Context, q models.FolkloreFilter) ([]models.Folklore, error) {
	return uc.repo.GetByQuery(ctx, q)
}
