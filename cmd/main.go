package main

import (
	"github.com/taekwondodev/go-PassKey-Authentication/internal/api"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/config"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/controller"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/db"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/repository"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/service"
	"github.com/taekwondodev/go-PassKey-Authentication/pkg"
)

func main() {
	pool := Must(config.Connect())
	defer pool.Close()
	queries := db.New(pool)

	redis := Must(config.ConnectRedis())
	defer redis.Client.Close()

	webauthn := Must(config.InitWebAuthn())
	jwt := Must(pkg.NewJWT())
	authRepo := repository.New(queries, redis)
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
