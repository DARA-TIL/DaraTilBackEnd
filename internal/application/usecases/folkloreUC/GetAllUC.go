package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllFolkloreUC struct {
	repo repo.FolkloreRepo
}

func NewGetAllFolkloreUC(repo repo.FolkloreRepo) *GetAllFolkloreUC {
	return &GetAllFolkloreUC{
		repo: repo,
	}
}

func (uc *GetAllFolkloreUC) Execute(ctx context.Context) ([]models.Folklore, error) {
	return uc.repo.GetAll(ctx)
}
