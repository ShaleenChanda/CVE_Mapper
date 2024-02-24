package pkgvulnmapper

import (
	"github.com/CloudDefenseAI/cve-mapper/models"
)

func VulnerablePackageFinder (
	packageName string, 
	packageVersion string, 
	cveInfo datamodel.CVEMap,
) (bool, datamodel.VulnerablityInfo) {

	/*
		Tasks:
		1. (Completed) get the list of CVEs for the packageName.
		2. Traverse the list and check for version match in chosen CVE.
		3. Check if version matches
		3. (Completed) Format the output and return.
	*/

	var cveListOfPackage []datamodel.CVEInfo = cveInfo[packageName]

	for _, cveItem := range cveListOfPackage {
		if vulnerabilityByVersion(packageVersion, cveItem.VersionInfo) {
			return true, datamodel.VulnerablityInfo{
				PackageName: packageName,
				VersionInfo: packageVersion,
				CVEID: cveItem.CVEID,
				Severity: cveItem.Impact.Severity,
			}
		}
	}

	// if no vulnerability found associated with the packageName.
	return false, datamodel.VulnerablityInfo{}
}

func vulnerabilityByVersion(
	packageVersion string, 
	versionInfo datamodel.VersionInfo,
) bool {
	/*
		Tasks:
	*/

	return true
}


