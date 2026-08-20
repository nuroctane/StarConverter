// Command starconverter-lab orchestrates disposable image and crash-consistency tests.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nuroctane/StarConverter/lab/internal/crashmodel"
	"github.com/nuroctane/StarConverter/lab/internal/matrix"
)

func main() {
	if len(os.Args) != 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "matrix":
		printMatrix()
	case "json":
		printJSON()
	case "crashes":
		printCrashes()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func printCrashes() {
	campaign, err := crashmodel.Campaign()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[BLOCKED] invalid crash protocol: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[ STARCONVERTER :: CRASH CAMPAIGN ]")
	fmt.Println("[SAFE] model only; no images or devices are modified")
	fmt.Println()
	for index, injection := range campaign {
		fmt.Printf("%02d :: after=%-22s fault=%-19s recover=%s\n", index+1, injection.After, injection.Fault, injection.Recovery)
	}
}

func printMatrix() {
	fmt.Println("[ STARCONVERTER :: LAB ]")
	fmt.Println("[SAFE] matrix description only; no images or devices are modified")
	fmt.Println()
	for index, test := range matrix.Baseline() {
		if err := matrix.Validate(test); err != nil {
			fmt.Fprintf(os.Stderr, "[BLOCKED] %s :: %v\n", test.Name, err)
			os.Exit(1)
		}
		fmt.Printf(
			"%02d :: %-30s %s -> %s / sector=%d / cluster=%d / %s\n",
			index+1,
			test.Name,
			test.SourceFS,
			test.TargetFS,
			test.SectorBytes,
			test.ClusterBytes,
			test.Guarantee,
		)
	}
}

func printJSON() {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(matrix.Baseline()); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] encode matrix: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("Usage: starconverter-lab <matrix|json|crashes|help>")
}
