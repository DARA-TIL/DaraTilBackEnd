package userUC

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"

	"golang.org/x/crypto/bcrypt"
)

type CreateUserUC struct {
	repo repo.UserRepo
}

func NewCreateUserUC(repo repo.UserRepo) *CreateUserUC {
	return &CreateUserUC{repo: repo}
}

func (uc *CreateUserUC) Execute(ctx context.Context, user models.User, authProvider string) (*models.User, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, domErr.ErrInternal
	}
	user.Password = string(hashed)
	user.AuthProvider = authProvider
	return uc.repo.Create(ctx, user)
}
