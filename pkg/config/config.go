package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"os"
)

func Load(localEnvFile string) error {
	err := godotenv.Load(localEnvFile)
	if err != nil {
		return err
	}

	return nil
}

func Check(envVars []string) error {

	if len(envVars) == 0 {
		return fmt.Errorf("need to indicate slice of variables")
	}

	emptyVars := make([]string, 0)
	for _, e := range envVars {
		if os.Getenv(e) == "" {
			fmt.Println("check var: ", os.Getenv(e))
			emptyVars = append(emptyVars, e)
		}
	}

	if len(emptyVars) > 0 {
		fmt.Println("EMPTY ENVIRONMENT VARIABLES: ")
		for _, e := range envVars {
			fmt.Println(e)
		}
		lenAllVars := len(envVars)
		lenEmptyVars := len(emptyVars)
		return fmt.Errorf("environment needs %d variables, but received only %d", lenAllVars, lenAllVars-lenEmptyVars)
	}
	return nil
}
