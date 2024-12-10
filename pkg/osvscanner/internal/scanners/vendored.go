package scanners

// const (
// 	// This value may need to be tweaked, or be provided as a configurable flag.
// 	determineVersionThreshold = 0.15
// 	maxDetermineVersionFiles  = 10000
// )

// var (
// 	vendoredLibNames = map[string]struct{}{
// 		"3rdparty":    {},
// 		"dep":         {},
// 		"deps":        {},
// 		"thirdparty":  {},
// 		"third-party": {},
// 		"third_party": {},
// 		"libs":        {},
// 		"external":    {},
// 		"externals":   {},
// 		"vendor":      {},
// 		"vendored":    {},
// 	}
// )

// TODO(V2): Migrate to extractor + use determineversions client

// func ScanDirWithVendoredLibs(r reporter.Reporter, path string) ([]imodels.ScannedPackage, error) {
// 	r.Infof("Scanning directory for vendored libs: %s\n", path)
// 	entries, err := os.ReadDir(path)
// 	if err != nil {
// 		return nil, err
// 	}

// 	var packages []imodels.ScannedPackage
// 	for _, entry := range entries {
// 		if !entry.IsDir() {
// 			continue
// 		}

// 		libPath := filepath.Join(path, entry.Name())

// 		r.Infof("Scanning potential vendored dir: %s\n", libPath)
// 		// TODO: make this a goroutine to parallelise this operation
// 		results, err := queryDetermineVersions(libPath)
// 		if err != nil {
// 			r.Infof("Error scanning sub-directory '%s' with error: %v", libPath, err)
// 			continue
// 		}

// 		if len(results.Matches) > 0 && results.Matches[0].Score > determineVersionThreshold {
// 			match := results.Matches[0]
// 			r.Infof("Identified %s as %s at %s.\n", libPath, match.RepoInfo.Address, match.RepoInfo.Commit)
// 			packages = append(packages, createCommitQueryPackage(match.RepoInfo.Commit, libPath))
// 		}
// 	}

// 	return packages, nil
// }

// func createCommitQueryPackage(commit string, source string) imodels.ScannedPackage {
// 	return imodels.ScannedPackage{
// 		Commit: commit,
// 		Source: models.SourceInfo{
// 			Path: source,
// 			Type: "git",
// 		},
// 	}
// }

// func queryDetermineVersions(repoDir string) (*osv.DetermineVersionResponse, error) {
// 	fileExts := []string{
// 		".hpp",
// 		".h",
// 		".hh",
// 		".cc",
// 		".c",
// 		".cpp",
// 	}

// 	var hashes []osv.DetermineVersionHash
// 	if err := filepath.Walk(repoDir, func(p string, info fs.FileInfo, _ error) error {
// 		if info.IsDir() {
// 			if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
// 				// Found a git repo, stop here as otherwise we may get duplicated
// 				// results with our regular git commit scanning.
// 				return filepath.SkipDir
// 			}
// 			if _, ok := vendoredLibNames[strings.ToLower(info.Name())]; ok {
// 				// Ignore nested vendored libraries, as they can cause bad matches.
// 				return filepath.SkipDir
// 			}

// 			return nil
// 		}
// 		for _, ext := range fileExts {
// 			if filepath.Ext(p) == ext {
// 				buf, err := os.ReadFile(p)
// 				if err != nil {
// 					return err
// 				}
// 				hash := md5.Sum(buf) //nolint:gosec
// 				hashes = append(hashes, osv.DetermineVersionHash{
// 					Path: strings.ReplaceAll(p, repoDir, ""),
// 					Hash: hash[:],
// 				})
// 				if len(hashes) > maxDetermineVersionFiles {
// 					return errors.New("too many files to hash")
// 				}
// 			}
// 		}

// 		return nil
// 	}); err != nil {
// 		return nil, fmt.Errorf("failed during hashing: %w", err)
// 	}

// 	result, err := osv.MakeDetermineVersionRequest(filepath.Base(repoDir), hashes)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to determine versions: %w", err)
// 	}

// 	return result, nil
// }
