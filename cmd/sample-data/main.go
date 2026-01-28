package main

import (
	"log"

	"github.com/hootmeow/Vuln-Strix/internal/sampledata"
)

func main() {
	if err := sampledata.Generate("samples"); err != nil {
		log.Fatalf("Failed to generate sample data: %v", err)
	}
	log.Println("Sample data generated successfully in 'samples/' directory.")
}
