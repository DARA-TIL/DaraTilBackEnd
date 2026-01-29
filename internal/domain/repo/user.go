package repo

import "DaraTilBackendV2/internal/domain/models"

type UserRepo interface {
	Create(user models.User) (models.User, error)
	GetByEmail(email string) (models.User, error)
	GetByID(id int) (models.User, error)
	Update(user models.User) (models.User, error)
	GetAll() ([]models.User, error)
	GetLikedFolklore(id int) ([]models.User, error)
}
