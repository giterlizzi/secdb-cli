// SPDX-License-Identifier: Apache-2.0

package meta

// export VERSION=`git describe --tags --abbrev=0`
// export DATE=`date -u '+%Y-%m-%dT%H:%M:%SZ'`
// export COMMIT_HASH=`git rev-parse HEAD`

// go build -a -ldflags "-X github.com/giterlizzi/secdb-cli/internal/meta.Version=$VERSION" -o secdb

var (
	// Version is the version of the program - Git tag - git describe --tags --always
	Version = "v0.0.0"

	// CommitHash is the commit hash of the program - git rev-parse HEAD
	CommitHash = "0"

	// Branch is the branch of the program
	Branch = "0"

	// Date is the date of the build - date -u '+%Y-%m-%dT%H:%M:%SZ'
	BuildDate = "0"
)
