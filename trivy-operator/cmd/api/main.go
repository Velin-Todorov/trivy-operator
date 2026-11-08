package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var dataDir = "/data"

type vulnerability struct {
	ID               string `json:"VulnerabilityID"`
	PkgID            string `json:"PkgID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Status           string `json:"Status"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	Severity         string `json:"Severity"`
}

type result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []vulnerability `json:"Vulnerabilities"`
}

type osInfo struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type metadata struct {
	OS          osInfo   `json:"OS"`
	ImageID     string   `json:"ImageID"`
	DiffIDs     []string `json:"DiffIDs"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

// trivyResult holds the data from 1 trivy scan
type trivyResult struct {
	SchemaVersion int       `json:"SchemaVersion"`
	CreatedAt     time.Time `json:"CreatedAt"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Metadata      metadata  `json:"Metadata"`
	Results       []result  `json:"Results"`
}

func main() {
	http.HandleFunc("/scans", getScans)
	http.HandleFunc("/scans/{id}", getScansById)
	http.HandleFunc("/healthz", health)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// getScans returns all the results from all the scans
func getScans(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		http.Error(w, "Failed to read data", 500)
		return
	}

	queryParams := r.URL.Query()
	image := queryParams.Get("image")

	results := make([]trivyResult, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		var result trivyResult
		jsonFile, err := os.ReadFile(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			log.Printf("read %s: %v", entry.Name(), err)
			continue
		}

		err = json.Unmarshal(jsonFile, &result)
		if err != nil {
			log.Printf("deserializing %s: %v", entry.Name(), err)
			continue
		}

		if len(image) > 0 {
			if strings.HasPrefix(result.ArtifactName, image) {
				results = append(results, result)
			}
		} else {
			results = append(results, result)
		}
	}

	limit, _ := strconv.Atoi(queryParams.Get("limit"))
	offset, _ := strconv.Atoi(queryParams.Get("offset"))
	if limit < 0 {
		limit = 0
	}
	if offset < 0 {
		offset = 0
	}

	if offset > len(results) {
		offset = len(results)
	}
	end := len(results)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	results = results[offset:end]

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("encode /scans response: %v", err)
	}
}

// getScansById fetches a scan by ID
func getScansById(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidID(id) {
		http.Error(w, "Bad Request", 400)
		return
	}

	jsonFile, err := os.ReadFile(filepath.Join(dataDir, id+".json"))
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		http.Error(w, "Internal error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(jsonFile); err != nil {
		log.Printf("write /scans/%s response: %v", id, err)
	}
}

func isValidID(id string) bool {
	if len(id) != 16 {
		return false
	}

	_, err := strconv.ParseUint(id, 16, 64)
	return err == nil
}
