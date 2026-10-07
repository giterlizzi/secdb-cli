// SPDX-License-Identifier: Apache-2.0

// Package ci detects the CI environment and its provenance metadata.
package ci

import (
	"fmt"
	"os"
	"strings"
)

// Env is the detected CI environment and its provenance metadata.
type Env struct {
	Name       string `json:"name,omitempty"`
	Project    string `json:"project,omitempty"`
	ProjectURL string `json:"project_url,omitempty"`
	RunURL     string `json:"run_url,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Author     string `json:"author,omitempty"`
}

// Detect returns the CI environment the process is running in, or a zero Env
// (Name == "") when not in a recognized CI.
func Detect() Env {
	switch {
	case os.Getenv("GITLAB_CI") != "":
		return gitLabEnv()
	case os.Getenv("GITEA_ACTIONS") != "":
		// Gitea Actions also sets GITHUB_ACTIONS and the GITHUB_* variables,
		// so it must be checked first.
		env := gitHubEnv()
		env.Name = "gitea"
		return env
	case os.Getenv("GITHUB_ACTIONS") != "":
		return gitHubEnv()
	case os.Getenv("CI") != "":
		return Env{Name: "CI"}
	default:
		return Env{}
	}
}

func gitLabEnv() Env {
	return Env{
		Name:       "gitlab",
		Project:    os.Getenv("CI_PROJECT_NAME"),
		ProjectURL: os.Getenv("CI_PROJECT_URL"),
		RunURL:     os.Getenv("CI_PIPELINE_URL"),
		Ref:        os.Getenv("CI_COMMIT_REF_NAME"),
		Commit:     os.Getenv("CI_COMMIT_SHA"),
		Tag:        os.Getenv("CI_COMMIT_TAG"),
		Branch:     os.Getenv("CI_COMMIT_BRANCH"),
		Author:     os.Getenv("CI_COMMIT_AUTHOR"),
	}
}

// gitHubEnv reads the GitHub Actions variables, which Gitea Actions sets too.
func gitHubEnv() Env {
	var branch, tag string
	switch os.Getenv("GITHUB_REF_TYPE") {
	case "branch":
		branch = os.Getenv("GITHUB_REF_NAME")
	case "tag":
		tag = os.Getenv("GITHUB_REF_NAME")
	}

	server := os.Getenv("GITHUB_SERVER_URL")
	repo := os.Getenv("GITHUB_REPOSITORY")

	return Env{
		Name:       "github",
		Project:    repo,
		ProjectURL: fmt.Sprintf("%s/%s", server, repo),
		RunURL:     fmt.Sprintf("%s/%s/actions/runs/%s", server, repo, os.Getenv("GITHUB_RUN_ID")),
		Ref:        os.Getenv("GITHUB_REF"),
		Commit:     os.Getenv("GITHUB_SHA"),
		Author:     os.Getenv("GITHUB_ACTOR"),
		Tag:        tag,
		Branch:     branch,
	}
}

// DisplayName returns the CI name for people ("GitHub Actions", "GitLab CI"),
// or Name as is for any other CI.
func (e Env) DisplayName() string {
	switch e.Name {
	case "github":
		return "GitHub Actions"
	case "gitlab":
		return "GitLab CI"
	case "gitea":
		return "Gitea Actions"
	default:
		return e.Name
	}
}

// ShortCommit returns the commit SHA abbreviated to 7 characters.
func (e Env) ShortCommit() string {
	if len(e.Commit) > 7 {
		return e.Commit[:7]
	}
	return e.Commit
}

// Summary describes the run in one line, e.g. "GitHub Actions, org/repo,
// main @ 0123456" (a tag reads "tag v1.0.0 @ 0123456"); the parts that aren't
// known are left out. It is empty outside CI.
func (e Env) Summary() string {
	if e.Name == "" {
		return ""
	}

	parts := []string{e.DisplayName()}
	if e.Project != "" {
		parts = append(parts, e.Project)
	}

	ref := e.Branch
	if ref == "" && e.Tag != "" {
		ref = "tag " + e.Tag
	}
	switch commit := e.ShortCommit(); {
	case commit != "" && ref != "":
		ref += " @ " + commit
	case commit != "":
		ref = commit
	}
	if ref != "" {
		parts = append(parts, ref)
	}

	return strings.Join(parts, ", ")
}
