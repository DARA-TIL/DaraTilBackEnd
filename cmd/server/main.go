package main

import (
	"DaraTilBackendV2/internal/config"
	"fmt"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
}
