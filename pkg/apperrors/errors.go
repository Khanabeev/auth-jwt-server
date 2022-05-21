package apperrors

import "net/http"

type AppError struct {
	Code    int    `json:",omitempty"`
	Message string `json:"message"`
}

func (ae *AppError) AsMessage() *AppError {
	return &AppError{
		Message: ae.Message,
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

func NewValidationError(message string) *AppError {
	return &AppError{
		Message: message,
		Code:    http.StatusUnprocessableEntity,
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
