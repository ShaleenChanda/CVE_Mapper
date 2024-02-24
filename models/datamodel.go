// Package datamodel defines the data structures used for handling CVE information.
package datamodel

// VersionInfo represents the version information of a package.
type VersionInfo struct {
	PackageVersionExact          string `json:"package_versionExact"`
	PackageVersionStartIncluding string `json:"package_versionStartIncluding"`
	PackageVersionStartExcluding string `json:"package_versionStartExcluding"`
	PackageVersionEndIncluding   string `json:"package_versionEndIncluding"`
	PackageVersionEndExcluding   string `json:"package_versionEndExcluding"`
}

// Impact represents the impact metrics of a CVE.
type Impact struct {
	Metric              string `json:"metric"`
	Severity            string `json:"severity"`
	ExploitabilityScore string `json:"exploitabilityScore"`
	ImpactScore         string `json:"impactScore"`
}

// CVEInfo represents the information of a CVE.
type CVEInfo struct {
	CVEID       string      `json:"CVE_ID"`
	PackageName string      `json:"package_name"`
	CPE         string      `json:"cpe"`
	VersionInfo VersionInfo `json:"version_info"`
	Impact      Impact      `json:"impact"`
}

// CVEMap is a map where the key is a package name and the value is a slice of CVEInfo objects.
type CVEMap map[string][]CVEInfo

// VulnerablityInfo represents the information of a vulnerability of a package/version.
type VulnerablityInfo struct {
	PackageName string
	VersionInfo string
	CVEID 	 string 
	Severity string
}