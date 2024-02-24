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

	var vulnInfoList []datamodel.VulnerablityInfo = pkgvulnmapper.VulnerablePackageFinder("autocad_plant_3d", "2040", infoMap)

	for _, vulnInfo := range vulnInfoList {
		fmt.Println(vulnInfo)
	}

	fmt.Println(len(vulnInfoList))

}


