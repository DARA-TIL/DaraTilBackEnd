package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type LvlUpUC struct {
	repo repo.UserRepo
}

func NewLvlUpUC(repo repo.UserRepo) *LvlUpUC {
	return &LvlUpUC{repo: repo}
}

func (u *LvlUpUC) Execute(ctx context.Context, userId, xpAdded int) (int, int, bool, *models.User, error) {
	return u.repo.LvlUp(ctx, userId, xpAdded)
}
