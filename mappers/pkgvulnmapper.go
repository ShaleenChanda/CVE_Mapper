package pkgvulnmapper

import (
	"fmt"
	"github.com/CloudDefenseAI/cve-mapper/models"
	"strings"
)

// VulnerablePackageFinder finds the vulnerabilities of a package.
//
//	arguments: {
//			packageName: name of the package
//			packageVersion: version of the package
//			cveInfo: map of CVE information
//	}
func VulnerablePackageFinder(
	packageName string,
	packageVersion string,
	cveInfo datamodel.CVEMap,
) ([]datamodel.VulnerablityInfo, error) {

	cveListOfPackage, ok := cveInfo[packageName]

	// If Package is not found in the CVE data,
	// return empty vulnerabilityList
	if !ok || len(cveListOfPackage) == 0 {
		return []datamodel.VulnerablityInfo{}, fmt.Errorf("package not found in the CVE database")
	}

	var vulnerabilityList []datamodel.VulnerablityInfo
	// map to maintain unique vulnerabilities
	uniqueCVEMap := make(map[string]int)
	
	for _, cveItem := range cveListOfPackage {
		if matchVulnerabilityByVersion(packageVersion, cveItem.VersionInfo) {
			// If the vulnerability is not already added to the list, add it to the list
			if uniqueCVEMap[cveItem.CVEID] < 1 {
				uniqueCVEMap[cveItem.CVEID] = 1
				vulnerabilityList = append(vulnerabilityList, datamodel.VulnerablityInfo{
					PackageName: packageName,
					VersionInfo: packageVersion,
					CVEID:       cveItem.CVEID,
					Severity:    cveItem.Impact.Severity,
				})
			}
		}
	}

	// vulnerabilityList will be empty if no vulnerability is found.
	return vulnerabilityList, nil
}

// matchVulnerabilityByVersion checks if the packageVersion is vulnerable to the given CVE.
//
//	arguments: {
//			packageVersion: version of the package
//			versionInfo: version information of the package from the CVE
//	}
func matchVulnerabilityByVersion(
	packageVersion string,
	versionInfo datamodel.VersionInfo,
) bool {
	// If Exact match exists between packageVersion and versionInfo.PackageVersionStartIncluding
	if versionInfo.PackageVersionExact != "NA" {
		standardizeInfoVersion := standardizeVersion(versionInfo.PackageVersionExact)
		standardizePackageVersion := standardizeVersion(packageVersion)

		// If Exact match exists between packageVersion and versionInfo.PackageVersionExact
		if standardizeInfoVersion == standardizePackageVersion {
			return true
		}
	}

	return false
}

// standardizeVersion standardizes the version string to a 4 part version string.
//
//	arguments: {
//			version: version string
//	}
func standardizeVersion(version string) string {
	// Trim leading and trailing dots
	version = strings.Trim(version, ".")

	// If the version is empty after trimming, return "0.0.0.0"
	if version == "" {
		return "0.0.0.0"
	}

	parts := strings.Split(version, ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	return strings.Join(parts, ".")
}
