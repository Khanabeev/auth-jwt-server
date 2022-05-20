package main

import (
	"auth-jwt-server/internal/composites"
	"auth-jwt-server/pkg/config"
	"auth-jwt-server/pkg/logging"
	"github.com/julienschmidt/httprouter"
	"log"
)

func main() {
	logger := logging.GetLogger()
	logger.Info("Sanity check...")
	sanityCheck()

	logger.Info("Create composites... ")
	dbComposite, err := composites.NewMySQLComposite()
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("Router initializing...")
	router := httprouter.New()
	authComposite, err := composites.NewAuthComposite(dbComposite)
	if err != nil {
		logger.Fatal(err)
	}
	authComposite.Handler.Register(router)
}

func sanityCheck() {
	err := config.Load("../.env")
	if err != nil {
		log.Fatal(err.Error())
	}
	checkVars := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWORD",
		"DB_ADDRESS",
		"DB_PORT",
		"DB_NAME",
	}

	err = config.Check(checkVars)
	if err != nil {
		log.Fatal(err)
	}
}
