package userUC

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"

	"golang.org/x/crypto/bcrypt"
)

type UpdateUserUC struct {
	repo repo.UserRepo
}

func NewUpdateUserUC(repo repo.UserRepo) *UpdateUserUC {
	return &UpdateUserUC{
		repo: repo,
	}
}
func (uc *UpdateUserUC) Execute(ctx context.Context, id int, fields models.UserUpdatableFields) (*models.User, error) {
	if fields.Password != nil {
		hashed, err := bcrypt.GenerateFromPassword([]byte(*fields.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, domErr.ErrInternal
		}
		hashStr := string(hashed)
		fields.Password = &hashStr
	}
	return uc.repo.Update(ctx, id, fields)
}
