package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllFolkloreUC struct {
	Repo repo.FolkloreRepo
}

func NewGetAllFolkloreUC(repo repo.FolkloreRepo) *GetAllFolkloreUC {
	return &GetAllFolkloreUC{
		Repo: repo,
	}
}

func (uc *GetAllFolkloreUC) Execute(ctx context.Context) ([]models.Folklore, error) {
	return uc.Repo.GetAll(ctx)
}
