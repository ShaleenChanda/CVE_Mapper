package main

import (
	"fmt"
	"github.com/CloudDefenseAI/cve-mapper/filehandlers"
	"github.com/CloudDefenseAI/cve-mapper/models"
	"github.com/CloudDefenseAI/cve-mapper/mappers"
)

func main() {
	var infoMap datamodel.CVEMap
	var error error
	infoMap , error = jsonhandler.LoadCVEsFromJSON("data/transformed_data.json")

	if error != nil {	
		fmt.Println(error)
		return
	}

	vulnInfoList, error := pkgvulnmapper.VulnerablePackageFinder("opera_browser", "7.20", infoMap)

	if error != nil {
		fmt.Println(error)
		return
	}

	for _, vulnInfo := range vulnInfoList {
		fmt.Println(vulnInfo)
	}

	fmt.Println(len(vulnInfoList))

}


