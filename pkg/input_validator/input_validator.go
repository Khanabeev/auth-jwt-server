package input_validator

import (
	"auth-jwt-server/pkg/logging"
	"fmt"
	"github.com/go-playground/validator/v10"
)

type InputValidator struct {
}

func NewInputValidator() *InputValidator {
	return &InputValidator{}
}

func (iv *InputValidator) Validate(i interface{}) []string {
	v := validator.New()
	err := v.Struct(i)
	if err != nil {
		var renderedErrors []string
		for _, err := range err.(validator.ValidationErrors) {
			renderedErrors = append(renderedErrors, iv.getMessage(err))
		}

		return renderedErrors
	}

	return nil
}

func (iv *InputValidator) getMessage(fieldError validator.FieldError) string {
	// List of messages
	e := make(map[string]string)
	e["email"] = "Invalid email address"
	e["required"] = fmt.Sprintf("%s field is required", fieldError.Field())
	e["gte"] = fmt.Sprintf("%s lenght must be more or equal %s", fieldError.Field(), fieldError.Param())

	message, exists := e[fieldError.Tag()]
	if exists {
		return message
	} else {
		logger := logging.GetLogger()
		logger.Error("Unknown validation type error in InputValidator.getMessage() method")
		return "Unknown validation type error"
	}

}
