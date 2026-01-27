package interfaces

import "DaraTilBackendV2/internal/domain/models"

type FolkloreRepo interface {
	Create(folklore models.Folklore, translations map[string]models.FolkloreTranslation) (models.Folklore, error)
	GetByID(id uint) (models.Folklore, error)
	GetAll() ([]models.Folklore, error)
	Update(folklore models.Folklore) (models.Folklore, error)
	Delete(id uint) error
	ToggleLike(folkloreID, userID uint) (models.Folklore, bool, error)
	GetByQuery(query models.FolkloreFilter) (models.Folklore, error)
}
