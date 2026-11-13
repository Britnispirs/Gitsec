package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitClient_LiveRepo(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}

	client := NewClient(wd)

	if !client.IsGitRepository() {
		t.Fatalf("expected current directory to be a Git repository")
	}

	root, err := client.FindRepoRoot()
	if err != nil {
		t.Fatalf("FindRepoRoot() error: %v", err)
	}

	// Root should resolve to project base path
	if filepath.Base(root) != "gitsec" {
		t.Errorf("expected root base 'gitsec', got %s", filepath.Base(root))
	}

	headSHA, err := client.GetHeadCommitSHA()
	if err != nil {
		t.Fatalf("GetHeadCommitSHA() error: %v", err)
	}
	if len(headSHA) < 40 {
		t.Errorf("invalid HEAD commit SHA length: %s", headSHA)
	}

	branch, err := client.GetCurrentBranch()
	if err != nil {
		t.Fatalf("GetCurrentBranch() error: %v", err)
	}
	if branch != "main" {
		t.Logf("current branch: %s", branch)
	}

	treeSHA, err := client.GetTreeSHA()
	if err != nil {
		t.Fatalf("GetTreeSHA() error: %v", err)
	}
	if len(treeSHA) < 40 {
		t.Errorf("invalid Tree SHA length: %s", treeSHA)
	}
}

