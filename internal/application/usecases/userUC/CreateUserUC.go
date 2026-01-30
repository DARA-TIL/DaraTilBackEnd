package userUC

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"

	"golang.org/x/crypto/bcrypt"
)

type CreateUserUC struct {
	Repo repo.UserRepo
}

func NewCreateUserUC(repo repo.UserRepo) *CreateUserUC {
	return &CreateUserUC{Repo: repo}
}

func (uc *CreateUserUC) Execute(ctx context.Context, user models.User) (*models.User, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, domErr.ErrInternal
	}
	user.Password = string(hashed)
	return uc.Repo.Create(ctx, user)
}
