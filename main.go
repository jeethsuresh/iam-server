package main

import (
	"github.com/jeethsuresh/iam/db"
	"github.com/jeethsuresh/iam/internal/server"
)

func main() {
	dbProvider, err := db.OpenFromEnv()
	if err != nil {
		panic(err)
	}

	e := server.New(dbProvider)
	e.Logger.Fatal(e.Start(":8080"))
}
