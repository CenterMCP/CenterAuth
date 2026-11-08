package appversion

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// FeatureVersion is the user-facing semantic version. Bump the minor version
// for each feature change and the patch version for fixes.
const FeatureVersion = "0.1.0"

type Info struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	FeatureVersion string `json:"feature_version"`
	Revision       string `json:"revision"`
	Modified       bool   `json:"modified"`
	CommitTime     string `json:"commit_time,omitempty"`
	GoVersion      string `json:"go_version"`
}

// Current returns the semantic feature version plus VCS metadata embedded by
// the Go toolchain. The revision changes with every commit, while Modified is
// true when the binary was built from a working tree with uncommitted edits.
func Current() Info {
	info := Info{
		Name:           "CenterAuth",
		FeatureVersion: FeatureVersion,
		Revision:       "unknown",
		GoVersion:      runtime.Version(),
	}

	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				info.Revision = setting.Value
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			case "vcs.time":
				info.CommitTime = setting.Value
			}
		}
	}

	revision := info.Revision
	if revision == "" || revision == "unknown" {
		revision = "dev"
	} else if len(revision) > 12 {
		revision = revision[:12]
	}
	info.Version = FeatureVersion + "+" + revision
	if info.Modified {
		info.Version += ".dirty"
	}
	return info
}

func String() string {
	return strings.TrimSpace(Current().Version)
}
