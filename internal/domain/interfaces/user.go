package interfaces

import "DaraTilBackendV2/internal/domain/models"

type UserRepo interface {
	Create(user models.User) (models.User, error)
	GetByEmail(email string) (models.User, error)
	GetByID(id uint) (models.User, error)
	Update(user models.User) (models.User, error)
	GetAll() ([]models.User, error)
	GetLikedFolklore(id uint) ([]models.User, error)
}
