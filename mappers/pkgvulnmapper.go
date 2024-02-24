package pkgvulnmapper

import (
	"github.com/CloudDefenseAI/cve-mapper/models"
	"strings"
)

// VulnerablePackageFinder finds the vulnerabilities of a package.
// arguments: {
//		packageName: name of the package
//		packageVersion: version of the package
//		cveInfo: map of CVE information
// }
func VulnerablePackageFinder (
	packageName string, 
	packageVersion string, 
	cveInfo datamodel.CVEMap,
) ([]datamodel.VulnerablityInfo) {

	var cveListOfPackage []datamodel.CVEInfo = cveInfo[packageName]
	var vulnerabilityList []datamodel.VulnerablityInfo
	for _, cveItem := range cveListOfPackage {
		if matchVulnerabilityByVersion(packageVersion, cveItem.VersionInfo) {
			vulnerabilityList = append(vulnerabilityList, datamodel.VulnerablityInfo{
				PackageName: packageName,
				VersionInfo: packageVersion,
				CVEID:       cveItem.CVEID,
				Severity:    cveItem.Impact.Severity,
			})
		}
	}

	// vulnerabilityList will be empty if no vulnerability is found.
	return vulnerabilityList
}

// matchVulnerabilityByVersion checks if the packageVersion is vulnerable to the given CVE.
// arguments: {
//		packageVersion: version of the package
//		versionInfo: version information of the package from the CVE
// }
func matchVulnerabilityByVersion(
	packageVersion string, 
	versionInfo datamodel.VersionInfo,
) bool {
	// If Exact match is exists between packageVersion and versionInfo.PackageVersionStartIncluding
	if versionInfo.PackageVersionExact != "NA" {
		standardizeInfoVersion := standardizeVersion(versionInfo.PackageVersionExact)
		standardizePackageVersion := standardizeVersion(packageVersion)

		// If Exact match is exists between packageVersion and versionInfo.PackageVersionExact
		if standardizeInfoVersion == standardizePackageVersion {
			return true
		}
	}

	return false
}

// standardizeVersion standardizes the version string to a 4 part version string.
// arguments: {
//		version: version string
// }
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


