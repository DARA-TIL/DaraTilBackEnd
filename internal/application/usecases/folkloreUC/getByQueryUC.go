package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFolkloreByQueryUC struct {
	repo repo.FolkloreRepo
}

func NewGetFolkloreByQueryUC(repo repo.FolkloreRepo) GetFolkloreByQueryUC {
	return GetFolkloreByQueryUC{repo: repo}
}

func (uc GetFolkloreByQueryUC) Execute(ctx context.Context, q models.FolkloreFilter) ([]models.Folklore, error) {
	return uc.repo.GetByQuery(ctx, q)
}
