package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFolkloreByIDUC struct {
	repo repo.FolkloreRepo
}

func NewGetByFolkloreIDUC(repo repo.FolkloreRepo) *GetFolkloreByIDUC {
	return &GetFolkloreByIDUC{
		repo: repo,
	}
}
func (uc *GetFolkloreByIDUC) Execute(ctx context.Context, folkloreID int) (*models.Folklore, error) {
	return uc.repo.GetByID(ctx, folkloreID)
}
