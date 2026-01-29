package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFolkloreByQueryUC struct {
	Repo repo.FolkloreRepo
}

func NewGetFolkloreByQueryUC(repo repo.FolkloreRepo) GetFolkloreByQueryUC {
	return GetFolkloreByQueryUC{Repo: repo}
}

func (uc GetFolkloreByQueryUC) Execute(ctx context.Context, q models.FolkloreFilter) ([]models.Folklore, error) {
	return uc.Repo.GetByQuery(ctx, q)
}
