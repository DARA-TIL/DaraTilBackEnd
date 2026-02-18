package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.FolkloreRepo
}

func NewGetByFolkloreIDUC(repo repo.FolkloreRepo) *GetByIDUC {
	return &GetByIDUC{
		repo: repo,
	}
}
func (uc *GetByIDUC) Execute(ctx context.Context, folkloreID uint) (*models.Folklore, error) {
	return uc.repo.GetByID(ctx, folkloreID)
}
