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

func (u *LvlUpUC) Execute(ctx context.Context, userId uint, xpAdded int) models.LvlRet {
	return u.repo.LvlUp(ctx, userId, xpAdded)
}
