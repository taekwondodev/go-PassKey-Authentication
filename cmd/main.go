package main

import (
	"go-PassKey-Authentication/internal/config"
	"go-PassKey-Authentication/internal/db"
	"go-PassKey-Authentication/internal/repository"
)

func main() {
	pool := Must(config.Connect())
	defer pool.Close()

	queries := db.New(pool)
	userRepo := repository.New(queries)
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
