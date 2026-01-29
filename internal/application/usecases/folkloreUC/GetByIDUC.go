package folkloreUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetFolkloreByIDUC struct {
	Repo repo.FolkloreRepo
}

func NewGetByFolkloreIDUC(repo repo.FolkloreRepo) *GetFolkloreByIDUC {
	return &GetFolkloreByIDUC{
		Repo: repo,
	}
}
func (uc GetFolkloreByIDUC) Execute(ctx context.Context, folkloreID int) (*models.Folklore, error) {
	return uc.Repo.GetByID(ctx, folkloreID)
}
