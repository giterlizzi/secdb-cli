// SPDX-License-Identifier: Apache-2.0

// Package ci detects the CI environment and its provenance metadata.
package ci

import (
	"fmt"
	"os"
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
