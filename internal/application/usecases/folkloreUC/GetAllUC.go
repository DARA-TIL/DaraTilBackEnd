package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.FolkloreRepo
}

func NewGetAllUC(repo repo.FolkloreRepo) *GetAllUC {
	return &GetAllUC{
		repo: repo,
	}
}

func (uc *GetAllUC) Execute(ctx context.Context) ([]models.Folklore, error) {
	return uc.repo.GetAll(ctx)
}
