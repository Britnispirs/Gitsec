package cas

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Britnispirs/Gitsec/internal/models"
)

const (
	SecDir        = ".sec"
	ObjectsDir    = "objects"
	RefsDir       = "refs"
	RefsHeadsDir  = "refs/heads"
	DefaultBranch = "main"
	HeadFile      = "HEAD"
	ConfigFile    = "config.json"
)

// Store provides operations on the content-addressable storage.
type Store struct {
	rootDir string
	secDir  string
}

// NewStore initializes a Store reference for a given repository root.
func NewStore(rootDir string) *Store {
	return &Store{
		rootDir: rootDir,
		secDir:  filepath.Join(rootDir, SecDir),
	}
}

// SecPath returns the absolute path to .sec directory.
func (s *Store) SecPath() string {
	return s.secDir
}

// Init creates the .sec directory scaffolding if it does not already exist.
func (s *Store) Init() error {
	dirs := []string{
		s.secDir,
		filepath.Join(s.secDir, ObjectsDir),
		filepath.Join(s.secDir, RefsDir),
		filepath.Join(s.secDir, RefsHeadsDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	headPath := filepath.Join(s.secDir, HeadFile)
	if _, err := os.Stat(headPath); os.IsNotExist(err) {
		initialHead := fmt.Sprintf("ref: %s/%s\n", RefsHeadsDir, DefaultBranch)
		if err := os.WriteFile(headPath, []byte(initialHead), 0644); err != nil {
			return fmt.Errorf("failed to write HEAD file: %w", err)
		}
	}

	return nil
}

// ComputeObjectID calculates the canonical SHA-256 hash for an object.
// Format: Type + " " + SizeInBytes + "\0" + Payload
func ComputeObjectID(objType models.ObjectType, payload []byte) (string, []byte) {
	header := fmt.Sprintf("%s %d\x00", objType, len(payload))
	fullData := append([]byte(header), payload...)

	hasher := sha256.New()
	hasher.Write(fullData)
	hashBytes := hasher.Sum(nil)
	objectID := hex.EncodeToString(hashBytes)

	return objectID, fullData
}

// WriteObject writes raw object payload into the CAS, compressed with zlib.
func (s *Store) WriteObject(objType models.ObjectType, payload []byte) (string, error) {
	objectID, fullData := ComputeObjectID(objType, payload)

	dirPrefix := objectID[:2]
	fileName := objectID[2:]

	objDirPath := filepath.Join(s.secDir, ObjectsDir, dirPrefix)
	if err := os.MkdirAll(objDirPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create object directory %s: %w", objDirPath, err)
	}

	objFilePath := filepath.Join(objDirPath, fileName)
	if _, err := os.Stat(objFilePath); err == nil {
		// Object already exists (content-addressable deduplication)
		return objectID, nil
	}

	// Compress with zlib
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(fullData); err != nil {
		return "", fmt.Errorf("zlib compression failed: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("zlib close failed: %w", err)
	}

	// Write atomically using temporary file
	tmpFile, err := os.CreateTemp(objDirPath, "tmp_obj_*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp object file: %w", err)
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(compressed.Bytes()); err != nil {
		tmpFile.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("failed to write compressed data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpName, objFilePath); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("failed to commit object file: %w", err)
	}

	return objectID, nil
}

// ReadObject retrieves and decompresses an object by its SHA-256 ObjectID.
func (s *Store) ReadObject(objectID string) (models.ObjectType, []byte, error) {
	if len(objectID) != 64 {
		return "", nil, fmt.Errorf("invalid ObjectID length (expected 64, got %d)", len(objectID))
	}

	dirPrefix := objectID[:2]
	fileName := objectID[2:]
	objFilePath := filepath.Join(s.secDir, ObjectsDir, dirPrefix, fileName)

	compressedData, err := os.ReadFile(objFilePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read object %s: %w", objectID, err)
	}

	// Decompress with zlib
	zr, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return "", nil, fmt.Errorf("failed to initialize zlib reader: %w", err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decompress object data: %w", err)
	}

	// Verify SHA-256 integrity
	hasher := sha256.New()
	hasher.Write(decompressed)
	verifiedHash := hex.EncodeToString(hasher.Sum(nil))
	if verifiedHash != objectID {
		return "", nil, fmt.Errorf("object corruption detected: expected hash %s, got %s", objectID, verifiedHash)
	}

	// Parse header: Type + " " + Size + "\0" + Payload
	nullIdx := bytes.IndexByte(decompressed, 0)
	if nullIdx == -1 {
		return "", nil, fmt.Errorf("corrupt object format: missing null terminator in header")
	}

	header := string(decompressed[:nullIdx])
	payload := decompressed[nullIdx+1:]

	var objType string
	var sizeStr string
	_, err = fmt.Sscanf(header, "%s %s", &objType, &sizeStr)
	if err != nil {
		return "", nil, fmt.Errorf("malformed object header: %s", header)
	}

	size, err := strconv.Atoi(sizeStr)
	if err != nil || size != len(payload) {
		return "", nil, fmt.Errorf("object size mismatch: header declares %d, payload is %d", size, len(payload))
	}

	return models.ObjectType(objType), payload, nil
}

