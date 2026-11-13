package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Client provides interactions with the underlying Git repository.
type Client struct {
	workDir string
}

// NewClient creates a new Git client for the specified working directory.
func NewClient(workDir string) *Client {
	return &Client{workDir: workDir}
}

func (c *Client) runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if c.workDir != "" {
		cmd.Dir = c.workDir
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %s (%w)", strings.Join(args, " "), strings.TrimSpace(stderr.String()), err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// FindRepoRoot returns the top-level directory of the current Git repository.
func (c *Client) FindRepoRoot() (string, error) {
	return c.runGit("rev-parse", "--show-toplevel")
}

// GetHeadCommitSHA returns the 40-character SHA-1/SHA-256 hash of current HEAD.
func (c *Client) GetHeadCommitSHA() (string, error) {
	return c.runGit("rev-parse", "HEAD")
}

// GetCurrentBranch returns the name of the active branch, or "HEAD" if detached.
func (c *Client) GetCurrentBranch() (string, error) {
	branch, err := c.runGit("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return branch, nil
}

// GetTreeSHA returns the tree hash representing the files of the current HEAD.
func (c *Client) GetTreeSHA() (string, error) {
	return c.runGit("rev-parse", "HEAD^{tree}")
}

// IsWorkingTreeDirty returns true if there are uncommitted or untracked changes.
func (c *Client) IsWorkingTreeDirty() (bool, error) {
	output, err := c.runGit("status", "--porcelain")
	if err != nil {
		return false, err
	}
	return len(output) > 0, nil
}

// IsGitRepository checks whether the specified directory is part of a Git repo.
func (c *Client) IsGitRepository() bool {
	_, err := c.FindRepoRoot()
	return err == nil
}

