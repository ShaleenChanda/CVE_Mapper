package main

import (
	"fmt"
	"github.com/CloudDefenseAI/cve-mapper/filehandlers"
	"github.com/CloudDefenseAI/cve-mapper/models"
)


func main() {
	var cveInfo datamodel.CVEMap
	cveInfo, err := jsonhandler.LoadCVEsFromJSON("data/transformed_data.json")

	if err != nil {
		fmt.Printf("Failed to extract data from json with error: %s", err)
	}

	var count int = 0

	for key, value := range cveInfo {
		fmt.Printf("package name is : %s \n", key)
		fmt.Print(value)
		fmt.Println()
		count += len(value)
	}

	fmt.Printf("the total entries are : %d \n", count)

}