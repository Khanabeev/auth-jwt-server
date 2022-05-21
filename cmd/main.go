package main

import (
	"auth-jwt-server/internal/composites"
	"auth-jwt-server/pkg/config"
	"auth-jwt-server/pkg/logging"
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net"
	"net/http"
	"os"
	"time"
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

	authComposite, err := composites.NewAuthComposite(dbComposite)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Info("Router initializing...")
	router := mux.NewRouter()

	logger.Info("Register auth handler...")
	authComposite.Handler.Register(router)

	logger.Info("Start application...")
	start(router)
}

func start(router *mux.Router) {
	logger := logging.GetLogger()

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", address, port))
	if err != nil {
		panic(err)
	}
	server := &http.Server{
		Handler:      router,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	logger.Info(fmt.Sprintf("Server is listening %s:%s", address, port))
	log.Fatal(server.Serve(listener))
}

func sanityCheck() {
	err := config.Load(".env")
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
