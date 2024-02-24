package jsonhandler

import (
	"encoding/json"
	"github.com/CloudDefenseAI/cve-mapper/models"
	"os"
)

// function responsible for loading JSON data on CVEMap.
//
//	arguments : {
//			filepath: relative file path os JSON data
//	}
func LoadCVEsFromJSON(filepath string) (datamodel.CVEMap, error) {
	jsonData, err := os.ReadFile(filepath)

	if err != nil {
		return nil, err
	}

	var cveInfoMap datamodel.CVEMap
	err = json.Unmarshal(jsonData, &cveInfoMap)

	if err != nil {
		return nil, err
	}

	processedCVEInfoMap := processCVEData(cveInfoMap)

	return processedCVEInfoMap, nil
}

// function responsible for processing onloaded JSON data.
//
//	arguements : {
//			datamodel.CVEMap : onloaded CVE Data from JSON file
//	}
func processCVEData(infoMap datamodel.CVEMap) datamodel.CVEMap {
	for pkgName, cveInfos := range infoMap {
		for i, cveInfo := range cveInfos {
			if cveInfo.CVEID == "" {
				cveInfo.CVEID = "NA"
			}
			if cveInfo.PackageName == "" {
				cveInfo.PackageName = "NA"
			}
			if cveInfo.CPE == "" {
				cveInfo.CPE = "NA"
			}

			// Check VersionInfo fields
			if cveInfo.VersionInfo.PackageVersionExact == "" {
				cveInfo.VersionInfo.PackageVersionExact = "NA"
			}
			if cveInfo.VersionInfo.PackageVersionStartIncluding == "" {
				cveInfo.VersionInfo.PackageVersionStartIncluding = "NA"
			}
			if cveInfo.VersionInfo.PackageVersionStartExcluding == "" {
				cveInfo.VersionInfo.PackageVersionStartExcluding = "NA"
			}
			if cveInfo.VersionInfo.PackageVersionEndIncluding == "" {
				cveInfo.VersionInfo.PackageVersionEndIncluding = "NA"
			}
			if cveInfo.VersionInfo.PackageVersionEndExcluding == "" {
				cveInfo.VersionInfo.PackageVersionEndExcluding = "NA"
			}

			// Check Impact fields
			if cveInfo.Impact.Metric == "" {
				cveInfo.Impact.Metric = "NA"
			}
			if cveInfo.Impact.Severity == "" {
				cveInfo.Impact.Severity = "NA"
			}
			if cveInfo.Impact.ExploitabilityScore == "" {
				cveInfo.Impact.ExploitabilityScore = "NA"
			}
			if cveInfo.Impact.ImpactScore == "" {
				cveInfo.Impact.ImpactScore = "NA"
			}

			// Update the cveInfo in the slice
			cveInfos[i] = cveInfo
		}

		// Update the cveInfos in the map
		infoMap[pkgName] = cveInfos
	}

	return infoMap
}
