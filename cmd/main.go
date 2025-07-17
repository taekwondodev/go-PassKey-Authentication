package main

import (
	"go-PassKey-Authentication/internal/api"
	"go-PassKey-Authentication/internal/config"
	"go-PassKey-Authentication/internal/controller"
	"go-PassKey-Authentication/internal/db"
	"go-PassKey-Authentication/internal/repository"
	"go-PassKey-Authentication/internal/service"
	"go-PassKey-Authentication/pkg"
)

func main() {
	pool := Must(config.Connect())
	defer pool.Close()
	queries := db.New(pool)

	webauthn := Must(config.InitWebAuthn())
	jwt := Must(pkg.NewJWT())
	authRepo := repository.New(queries)
	authService := service.New(authRepo, jwt, webauthn)
	authController := controller.New(authService)

	router := api.SetupRoutes(authController)
	server := api.NewServer(":8080", router)

	server.StartWithGracefulShutdown()
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
