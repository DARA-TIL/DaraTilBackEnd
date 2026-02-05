package domErr

import "errors"

var (
	ErrNotFound     = errors.New("not found")      //404
	ErrUnauthorized = errors.New("unauthorized")   //401
	ErrForbidden    = errors.New("forbidden")      //403
	ErrConflict     = errors.New("conflict")       //409
	ErrInvalidInput = errors.New("invalid input")  // 422
	ErrInternal     = errors.New("internal error") //500
	ErrBadRequest   = errors.New("bad request")    //400
)
