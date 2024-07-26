package lockfilescalibr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                       `json:"version"`
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`
}

type NpmLockPackage struct {
	// For an aliased package, Name is the real package name
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`

	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`

	Link bool `json:"link,omitempty"`
}

type NpmLockfile struct {
	Version int `json:"lockfileVersion"`
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]NpmLockDependency `json:"dependencies,omitempty"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]NpmLockPackage `json:"packages,omitempty"`
}

const NpmEcosystem Ecosystem = "npm"

type npmPackageDetailsMap map[string]PackageDetails

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b PackageDetails) []string {
	// if either group includes no groups, then the package is in the "production" group
	if len(a.DepGroups) == 0 || len(b.DepGroups) == 0 {
		return nil
	}

	combined := make([]string, 0, len(a.DepGroups)+len(b.DepGroups))
	combined = append(combined, a.DepGroups...)
	combined = append(combined, b.DepGroups...)

	slices.Sort(combined)

	return slices.Compact(combined)
}

func (pdm npmPackageDetailsMap) add(key string, details PackageDetails) {
	existing, ok := pdm[key]

	if ok {
		details.DepGroups = mergeNpmDepsGroups(existing, details)
	}

	pdm[key] = details
}

func (dep NpmLockDependency) depGroups() []string {
	if dep.Dev && dep.Optional {
		return []string{"dev", "optional"}
	}
	if dep.Dev {
		return []string{"dev"}
	}
	if dep.Optional {
		return []string{"optional"}
	}

	return nil
}

func parseNpmLockDependencies(dependencies map[string]NpmLockDependency) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

	for name, detail := range dependencies {
		if detail.Dependencies != nil {
			nestedDeps := parseNpmLockDependencies(detail.Dependencies)
			for k, v := range nestedDeps {
				details.add(k, v)
			}
		}

		version := detail.Version
		finalVersion := version
		commit := ""

		// If the package is aliased, get the name and version
		if strings.HasPrefix(detail.Version, "npm:") {
			i := strings.LastIndex(detail.Version, "@")
			name = detail.Version[4:i]
			finalVersion = detail.Version[i+1:]
		}

		// we can't resolve a version from a "file:" dependency
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = ""
		} else {
			commit = tryExtractCommit(detail.Version)

			// if there is a commit, we want to deduplicate based on that rather than
			// the version (the versions must match anyway for the commits to match)
			//
			// we also don't actually know what the "version" is, so blank it
			if commit != "" {
				finalVersion = ""
				version = commit
			}
		}

		details.add(name+"@"+version, PackageDetails{
			Name:      name,
			Version:   finalVersion,
			Commit:    commit,
			DepGroups: detail.depGroups(),
		})
	}

	return details
}

func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

func (pkg NpmLockPackage) depGroups() []string {
	if pkg.Dev {
		return []string{"dev"}
	}
	if pkg.Optional {
		return []string{"optional"}
	}
	if pkg.DevOptional {
		return []string{"dev", "optional"}
	}

	return nil
}

func parseNpmLockPackages(packages map[string]NpmLockPackage) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

	for namePath, detail := range packages {
		if namePath == "" {
			continue
		}

		finalName := detail.Name
		if finalName == "" {
			finalName = extractNpmPackageName(namePath)
		}

		finalVersion := detail.Version

		commit := tryExtractCommit(detail.Resolved)

		// if there is a commit, we want to deduplicate based on that rather than
		// the version (the versions must match anyway for the commits to match)
		if commit != "" {
			finalVersion = commit
		}

		details.add(finalName+"@"+finalVersion, PackageDetails{
			Name:      finalName,
			Version:   detail.Version,
			Commit:    commit,
			DepGroups: detail.depGroups(),
		})
	}

	return details
}

func parseNpmLock(lockfile NpmLockfile) map[string]PackageDetails {
	if lockfile.Packages != nil {
		return parseNpmLockPackages(lockfile.Packages)
	}

	return parseNpmLockDependencies(lockfile.Dependencies)
}

type NpmLockExtractor struct{}

// Name of the extractor
func (e NpmLockExtractor) Name() string { return "javascript/packagelockjson" }

// Version of the extractor
func (e NpmLockExtractor) Version() int { return 0 }

func (e NpmLockExtractor) Requirements() Requirements {
	return Requirements{}
}

func (e NpmLockExtractor) FileRequired(path string, fileInfo fs.FileInfo) bool {
	return filepath.Base(path) == "package-lock.json"
}

func (e NpmLockExtractor) Extract(ctx context.Context, input *ScanInput) ([]*Inventory, error) {
	var parsedLockfile *NpmLockfile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := maps.Values(parseNpmLock(*parsedLockfile))
	inventories := make([]*Inventory, len(packages))

	for i, pkg := range packages {
		if pkg.DepGroups == nil {
			pkg.DepGroups = []string{}
		}

		inventories[i] = &Inventory{
			Name: pkg.Name,
			SourceCode: &SourceCodeIdentifier{
				Commit: pkg.Commit,
			},
			Version: pkg.Version,
			Metadata: DepGroupMetadata{
				DepGroupVals: pkg.DepGroups,
			},
			Locations: []string{input.Path},
		}
	}

	return inventories, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e NpmLockExtractor) ToPURL(i *Inventory) (*packageurl.PackageURL, error) {
	return &packageurl.PackageURL{
		Type:    packageurl.TypeNPM,
		Name:    i.Name,
		Version: i.Version,
	}, nil
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e NpmLockExtractor) ToCPEs(i *Inventory) ([]string, error) { return []string{}, nil }

func (e NpmLockExtractor) Ecosystem(i *Inventory) (string, error) {
	switch i.Extractor.(type) {
	case NpmLockExtractor:
		return string(NpmEcosystem), nil
	default:
		return "", ErrWrongExtractor
	}
}

var _ Extractor = NpmLockExtractor{}