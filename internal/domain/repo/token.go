package repo

import "DaraTilBackendV2/internal/domain/models"

type TokenRepo interface {
	Create(token models.Token) (models.Token, error)
	Refresh(token models.Token) (models.Token, error)
	Revoke(token models.Token) error
}
