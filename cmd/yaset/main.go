package main

import (
	"log"
	"github.com/whoissecure/yaset/internal/yaset"
)

func main() {
	if err := yaset.Run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
