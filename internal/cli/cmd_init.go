package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Britnispirs/Gitsec/internal/cas"
	"github.com/Britnispirs/Gitsec/internal/git"
)

type RepoConfig struct {
	SchemaVersion string   `json:"schema_version"`
	DefaultBranch string   `json:"default_branch"`
	Verifiers     []string `json:"verifiers"`
	PolicyProfile string   `json:"policy_profile"`
}

func (c *CLI) runInit(args []string) int {
	gitClient := git.NewClient("")

	if !gitClient.IsGitRepository() {
		fmt.Fprintln(c.stderr, "fatal: not a git repository (or any of the parent directories)")
		fmt.Fprintln(c.stderr, "Gitsec requires an initialized Git repository. Run 'git init' first.")
		return 1
	}

	repoRoot, err := gitClient.FindRepoRoot()
	if err != nil {
		fmt.Fprintf(c.stderr, "error: failed to locate git repository root: %v\n", err)
		return 1
	}

	secDir := filepath.Join(repoRoot, cas.SecDir)
	alreadyExisted := false
	if info, err := os.Stat(secDir); err == nil && info.IsDir() {
		alreadyExisted = true
	}

	store := cas.NewStore(repoRoot)
	if err := store.Init(); err != nil {
		fmt.Fprintf(c.stderr, "error: failed to initialize .sec storage: %v\n", err)
		return 1
	}

	// Detect current Git branch and bind to HEAD
	currentBranch, err := gitClient.GetCurrentBranch()
	if err != nil || currentBranch == "" {
		currentBranch = cas.DefaultBranch
	}

	headPath := filepath.Join(secDir, cas.HeadFile)
	headRefContent := fmt.Sprintf("ref: %s/%s\n", cas.RefsHeadsDir, currentBranch)
	_ = os.WriteFile(headPath, []byte(headRefContent), 0644)

	// Create default config.json if not present
	configPath := filepath.Join(secDir, cas.ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := RepoConfig{
			SchemaVersion: "1.0.0",
			DefaultBranch: currentBranch,
			Verifiers: []string{
				"secrets",
				"dependencies",
				"integrity",
			},
			PolicyProfile: "strict-zero-critical",
		}
		data, _ := json.MarshalIndent(defaultConfig, "", "  ")
		_ = os.WriteFile(configPath, append(data, '\n'), 0644)
	}

	// Output UX
	headCommit, _ := gitClient.GetHeadCommitSHA()
	shortCommit := "no commits yet"
	if len(headCommit) >= 7 {
		shortCommit = headCommit[:7]
	}

	if alreadyExisted {
		fmt.Fprintf(c.stdout, "Reinitialized existing Gitsec repository in %s/\n", secDir)
	} else {
		fmt.Fprintf(c.stdout, "Initialized empty Gitsec repository in %s/\n", secDir)
	}

	fmt.Fprintf(c.stdout, "  ● Tracking Git branch : %s\n", currentBranch)
	fmt.Fprintf(c.stdout, "  ● Bound Git commit    : %s\n", shortCommit)
	fmt.Fprintf(c.stdout, "  ● Storage engine      : CAS (zlib + SHA-256)\n")

	return 0
}
