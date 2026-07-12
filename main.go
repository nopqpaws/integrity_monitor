package main

import (
	"crypto/sha256" // sha256.New()
	"encoding/json" // json.MarshalIndent(), json.Unmarshal()
	"fmt"           // fmt.Sprintf(), fmt.Println(), fmt.Printf(), fmt.Errorf()
	"io"            // io.Copy()
	"io/fs"         // fs.DirEntry type in the walk callback
	"os"            // os.Open(), os.Stat(), os.ReadFile(), os.WriteFile(), os.Args, os.Exit()
	"path/filepath" // filepath.WalkDir(), Rel(), ToSlash(), Join(), Abs()
	"time"          // time.Now(), time.RFC3339
)

// default manifest filename when no path is given via CLI
const manifestName = ".integrity.json"

// FileEntry is what the baseline stores per file. json only sees exported (capital) fields
type FileEntry struct {
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// Manifest is the whole baseline, metadata plus a map of relative path to FileEntry
type Manifest struct {
	Root         string               `json:"root"`
	Created      string               `json:"created"`
	LastVerified string               `json:"last_verified"`
	Files        map[string]FileEntry `json:"files"` // key is relative path so that manifest stays portable
}

// VerificationResult collects what verify found, one slice per kind of change
type VerificationResult struct {
	Modified []string // files whose hash, size, or mtime changed
	Missing  []string // files in manifest but not on disk
	Added    []string // files on disk but not in manifest
}

// hashFile opens, hashes, and closes one file. Separate function because defer
// runs on function return, deferring inside a loop would hold every file open
func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close() // runs when the function returns

	h := sha256.New()
	// must check io.Copy cause a failed read would give the wrong hash
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// stat and hash every file, store each FileEntry under its root-relative path
func buildManifest(root string, files []string) (Manifest, error) {
	manifest := Manifest{
		Root:    root,
		Created: time.Now().Format(time.RFC3339), // stored as a string so the json stays human readable
		Files:   map[string]FileEntry{},
	}

	for _, f := range files {
		fileInfo, err := os.Stat(f)
		if err != nil {
			return Manifest{}, err
		}

		hash, err := hashFile(f)
		if err != nil {
			return Manifest{}, err
		}

		// relative path as the key so manifest stays portable
		relPath, err := filepath.Rel(root, f)
		if err != nil {
			return Manifest{}, err
		}

		// ToSlash so windows backslash paths still match when verified on linux
		manifest.Files[filepath.ToSlash(relPath)] = FileEntry{
			Hash:     hash,
			Size:     fileInfo.Size(),
			Modified: fileInfo.ModTime().Format(time.RFC3339),
		}
	}
	return manifest, nil
}

// Diff the dir against the baseline: flag missing files, size/mtime changes,
// hash mismatches (corruption with untouched mtime), and new files
func verifyIntegrity(root string, manifestPath string) (VerificationResult, error) {
	result := VerificationResult{}

	manifest, err := loadManifest(manifestPath)
	if err != nil {
		// %w wraps err so callers can still inspect it with errors.Is / errors.As
		return result, fmt.Errorf("failed to load manifest: %w", err)
	}

	// Walk the current state of the directory
	currentFiles, err := walkDirRecursive(root, manifestPath)
	if err != nil {
		return result, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Build a set of current relative paths for fast lookup
	currentSet := map[string]bool{}
	for _, absPath := range currentFiles {
		rel, err := filepath.Rel(root, absPath)
		if err != nil {
			return result, err
		}
		currentSet[filepath.ToSlash(rel)] = true
	}

	// Check every file recorded in the manifest
	for relPath, entry := range manifest.Files {
		absPath := filepath.Join(root, relPath)

		fileInfo, err := os.Stat(absPath)
		if os.IsNotExist(err) {
			result.Missing = append(result.Missing, relPath)
			continue
		}
		if err != nil {
			return result, err
		}

		// Check size and modification time first (cheap)
		if fileInfo.Size() != entry.Size ||
			fileInfo.ModTime().Format(time.RFC3339) != entry.Modified {
			result.Modified = append(result.Modified, relPath)
			continue
		}

		// Recompute hash to catch silent corruption (same mtime but different bytes)
		hash, err := hashFile(absPath)
		if err != nil {
			return result, err
		}
		if hash != entry.Hash {
			result.Modified = append(result.Modified, relPath)
		}
	}

	// Check for files on disk that aren't in the manifest
	for relPath := range currentSet {
		if _, exists := manifest.Files[relPath]; !exists {
			result.Added = append(result.Added, relPath)
		}
	}

	// update LastVerified and re save so the timestamp persists
	manifest.LastVerified = time.Now().Format(time.RFC3339)
	if err := saveManifest(manifest, manifestPath); err != nil {
		return result, err
	}

	return result, nil
}

func saveManifest(manifest Manifest, path string) error {
	// MarshalIndent instead of Marshal that way the manifest is readable and diffable
	data, err := json.MarshalIndent(manifest, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func loadManifest(path string) (Manifest, error) {
	var manifest Manifest

	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	err = json.Unmarshal(data, &manifest)
	if err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

// walkDirRecursive lists every file under root except the manifest itself,
// compared by absolute path so it never ends up in its own baseline
func walkDirRecursive(root string, manifestPath string) ([]string, error) {
	files := []string{}

	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return nil, err
	}

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error walking directory: %v\n", err)
			return nil // a non-nil return here would abort the whole walk
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		if !entry.IsDir() && absPath != absManifest {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// print the error and exit 1, saves repeating this all over main
func fail(err error) {
	fmt.Println("Error:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Println("usage: integrity_monitor baseline <dir> [manifest]")
		fmt.Println("       integrity_monitor verify <dir> [manifest]")
		os.Exit(1)
	}

	cmd, root := os.Args[1], os.Args[2]

	// default manifest path is just the filename, so it resolves against the
	// current directory instead of root. keeps the baseline out of the tree
	// it's protecting unless you explicitly ask for it to live there
	manifestPath := manifestName
	if len(os.Args) == 4 {
		manifestPath = os.Args[3]
	}

	switch cmd {
	case "baseline":
		files, err := walkDirRecursive(root, manifestPath)
		if err != nil {
			fail(err)
		}
		manifest, err := buildManifest(root, files)
		if err != nil {
			fail(err)
		}
		if err := saveManifest(manifest, manifestPath); err != nil {
			fail(err)
		}
		fmt.Printf("baseline saved: %d files in %s\n", len(manifest.Files), manifestPath)

	case "verify":
		result, err := verifyIntegrity(root, manifestPath)
		if err != nil {
			fail(err)
		}

		if len(result.Modified)+len(result.Missing)+len(result.Added) == 0 {
			fmt.Println("OK: no changes detected")
			return
		}
		for _, f := range result.Modified {
			fmt.Println("MODIFIED:", f)
		}
		for _, f := range result.Missing {
			fmt.Println("MISSING: ", f)
		}
		for _, f := range result.Added {
			fmt.Println("ADDED:   ", f)
		}
		// nonzero exit so a script or scheduled task can tell something changed
		os.Exit(1)

	default:
		fmt.Println("unknown command:", cmd)
		os.Exit(1)
	}
}
