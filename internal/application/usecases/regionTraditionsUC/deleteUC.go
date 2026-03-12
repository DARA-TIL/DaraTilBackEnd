package regionTraditionsUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteUC struct {
	repo repo.RegionTraditionRepo
}

func NewDeleteUC(repo repo.RegionTraditionRepo) *DeleteUC {
	return &DeleteUC{repo: repo}
}
func (uc *DeleteUC) Execute(ctx context.Context, id uint) error {
	return uc.repo.Delete(ctx, id)
}
