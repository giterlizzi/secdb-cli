// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

// ValidatePURLs returns only the well-formed PURLs, dropping the invalid ones.
func ValidatePURLs(purls []string) []string {
	valid := []string{}

	for _, p := range purls {
		purl, err := packageurl.FromString(p)
		if err != nil {
			slog.Debug("skipping invalid PURL", "value", p, "error", err)
			continue
		}
		s := purl.ToString()
		slog.Debug("found PURL", "purl", s)
		valid = append(valid, s)
	}

	return valid
}

// ReadPURLsFromSBOM extracts every component PURL from a CycloneDX JSON BOM,
// recursively.
func ReadPURLsFromSBOM(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SBOM %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)

	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode SBOM %s: %w", path, err)
	}

	if bom.Components == nil {
		return nil, errors.New("no Components found in SBOM file")
	}

	purls := []string{}

	var walk func(components *[]cdx.Component)

	walk = func(components *[]cdx.Component) {
		if components == nil {
			return
		}

		for _, c := range *components {
			if c.PackageURL != "" {
				purls = append(purls, c.PackageURL)
				slog.Debug("found PURL in CycloneDX SBOM component", slog.String("purl", c.PackageURL))
			}
			walk(c.Components)
		}
	}

	walk(bom.Components)

	return purls, nil
}
