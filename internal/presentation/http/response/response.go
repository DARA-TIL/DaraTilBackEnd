package response

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Success(c *gin.Context, status int, data any, extra ...gin.H) {
	body := gin.H{"data": data}
	if len(extra) > 0 && extra[0] != nil {
		for k, v := range extra[0] {
			if k == "data" {
				continue
			}
			body[k] = v
		}
	}
	c.JSON(status, body)
}

func Fail(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

func HandleDomainError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errs.ErrInvalidInput):
		Fail(c, http.StatusUnprocessableEntity, "invalid request")
	case errors.Is(err, errs.ErrUnauthorized):
		Fail(c, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, errs.ErrForbidden):
		Fail(c, http.StatusForbidden, "forbidden")
	case errors.Is(err, errs.ErrNotFound):
		Fail(c, http.StatusNotFound, "not found")
	case errors.Is(err, errs.ErrConflict):
		Fail(c, http.StatusConflict, "conflict")
	case errors.Is(err, errs.ErrInternal):
		Fail(c, http.StatusInternalServerError, "internal server error")
	default:
		// неизвестное - не светим
		Fail(c, http.StatusInternalServerError, "internal server error")
	}
}
