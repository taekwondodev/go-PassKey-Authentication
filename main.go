package main

import "go-PassKey-Authentication/config"

func main() {
	db := Must(config.New())
	Check(db.Init())
	defer db.Close()

}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func Check(err error) {
	if err != nil {
		panic(err)
	}
}
