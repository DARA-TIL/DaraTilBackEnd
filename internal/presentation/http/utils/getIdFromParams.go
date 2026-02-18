package utils

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"strconv"

	"github.com/gin-gonic/gin"
)

func GetIdFromParams(c *gin.Context) (*uint, error) {
	id := c.Param("id")
	if id == "" {
		return nil, domErr.ErrInvalidInput
	}
	idUint64, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return nil, domErr.ErrInvalidInput
	}
	idUint := uint(idUint64)
	return &idUint, nil
}
