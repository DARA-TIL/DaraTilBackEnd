package response

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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
	logger.Info("Sending success response", zap.Int("status", status), zap.Any("body", body))
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
	case errors.Is(err, errs.ErrLimitWithoutPremium):
		Fail(c, http.StatusLocked, "premium required: free daily limit exceeded")
	case errors.Is(err, errs.ErrNotFound):
		Fail(c, http.StatusNotFound, "not found")
	case errors.Is(err, errs.ErrConflict):
		Fail(c, http.StatusConflict, "conflict")
	case errors.Is(err, errs.ErrInternal):
		Fail(c, http.StatusInternalServerError, "internal server error")
	case errors.Is(err, errs.ErrAi):
		Fail(c, http.StatusInternalServerError, "ai error")
	default:
		// неизвестное - не светим
		Fail(c, http.StatusInternalServerError, "internal server error")
	}
}
