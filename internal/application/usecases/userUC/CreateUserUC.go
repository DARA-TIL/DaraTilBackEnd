package userUC

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"

	"golang.org/x/crypto/bcrypt"
)

type CreateUC struct {
	repo repo.UserRepo
}

func NewCreateUC(repo repo.UserRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, user models.User) (*models.User, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, domErr.ErrInternal
	}
	user.Password = string(hashed)
	return uc.repo.Create(ctx, user)
}
