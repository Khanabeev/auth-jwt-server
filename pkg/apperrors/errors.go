package apperrors

import (
	"net/http"
)

type AppError struct {
	Code    int      `json:",omitempty"`
	Message string   `json:"message"`
	Errors  []string `json:"errors,omitempty"`
}

func (ae *AppError) AsMessage() *AppError {
	return &AppError{
		Message: ae.Message,
		Errors:  ae.Errors,
	}
}

func NewNotFoundError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusNotFound,
	}
}

func NewUnexpectedError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusInternalServerError,
	}
}

func NewValidationError(message string, errorsList []string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusUnprocessableEntity,
		Errors:  errorsList,
	}
}

func NewBadRequest(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusBadRequest,
	}
}

func NewAuthenticationError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusBadRequest,
	}
}
