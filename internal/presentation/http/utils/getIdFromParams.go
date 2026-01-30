package utils

import (
	"DaraTilBackendV2/internal/domain/domErr"
	"strconv"

	"github.com/gin-gonic/gin"
)

func GetIdFromParams(c *gin.Context) (*int, error) {
	id := c.Param("id")
	if id == "" {
		return nil, domErr.ErrInvalidInput
	}
	idInt, err := strconv.Atoi(id)
	if err != nil {
		return nil, domErr.ErrInvalidInput
	}
	return &idInt, nil
}
