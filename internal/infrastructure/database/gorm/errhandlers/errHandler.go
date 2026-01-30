package errhandlers

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

func ErrHandler(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return errs.ErrInternal
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errs.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {

		switch pgErr.Code {

		case "23505": // unique_violation
			return errs.ErrConflict

		case "23502": // not_null_violation
			return errs.ErrInvalidInput

		case "23503": // foreign_key_violation
			return errs.ErrInvalidInput

		case "23514": // check_violation
			return errs.ErrInvalidInput

		case "28000", "28P01": // invalid authorization
			return errs.ErrUnauthorized

		case "42501": // insufficient privilege
			return errs.ErrForbidden

		default:
			// any other postgres error
			return errs.ErrInternal
		}
	}
	return errs.ErrInternal
}
