// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/xml"
	"log/slog"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

type pomProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []pomProperty `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dependency []pomDependency `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDependency `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

type pomProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// mavenParser handles pom.xml.
type mavenParser struct{}

func (mavenParser) Ecosystem() string  { return "maven" }
func (mavenParser) Patterns() []string { return []string{"pom.xml"} }

func (mavenParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var pom pomProject
	if err := xml.Unmarshal(content, &pom); err != nil {
		return nil, err
	}

	props := pomProperties(&pom)
	managedDeps := map[string]string{}

	for _, d := range pom.DependencyManagement.Dependencies.Dependency {
		managedDeps[d.GroupID+":"+d.ArtifactID] = resolvePomProperty(d.Version, props)
	}

	deps := make([]Dependency, 0, len(pom.Dependencies.Dependency))
	for _, d := range pom.Dependencies.Dependency {

		version := resolvePomProperty(d.Version, props)

		if version == "" {
			version = managedDeps[d.GroupID+":"+d.ArtifactID]
		}

		// skip empty version or raw property value
		if version == "" || strings.HasPrefix(version, "${") {
			slog.Debug("unresolved version... skip dependency", "group", d.GroupID, "artifact", d.ArtifactID)
			continue
		}

		slog.Debug("found dependency", "group", d.GroupID, "artifact", d.ArtifactID, "version", version)

		deps = append(deps, Dependency{
			PURL:      packageurl.NewPackageURL("maven", d.GroupID, d.ArtifactID, version, nil, "").ToString(),
			Ecosystem: "maven",
			Name:      d.GroupID + ":" + d.ArtifactID,
			Version:   version,
			Direct:    true,
		})
	}

	return deps, nil
}

// pomProperties return all POM properties
func pomProperties(pom *pomProject) map[string]string {
	props := map[string]string{}

	for _, p := range pom.Properties.Entries {
		key := p.XMLName.Local
		value := p.Value
		props[key] = value

		slog.Debug("decoded POM property", "key", key, "value", value)
	}

	return props
}

// resolvePomProperty return the POM property value
func resolvePomProperty(prop string, props map[string]string) string {
	prop = strings.TrimSpace(prop)
	if strings.HasPrefix(prop, "${") && strings.HasSuffix(prop, "}") {
		prop = prop[2 : len(prop)-1]
		return props[prop]
	}
	return prop
}
