package userUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUserUC struct {
	Repo repo.UserRepo
}

func NewUpdateUserUC(repo repo.UserRepo) *UpdateUserUC {
	return &UpdateUserUC{
		Repo: repo,
	}
}
func (uc *UpdateUserUC) Execute(ctx context.Context, id int, fields models.UserUpdatableFields) (*models.User, error) {
	return uc.Repo.Update(ctx, id, fields)
}
