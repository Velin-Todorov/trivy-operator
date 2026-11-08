/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"strings"

	"github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

// severityOrder lists trivy severities from highest to lowest. Used
// to translate a "minimum threshold" into the  comma-separated list
// trivy's --severity flag expects.
var severityOrder = []v1alpha1.Severity{
	v1alpha1.CRITICAL,
	v1alpha1.HIGH,
	v1alpha1.MEDIUM,
	v1alpha1.LOW,
	v1alpha1.UNKNOWN,
}

// severitiesAtAndAbove returns a comma-separated list of severities at or
// above the given threshold (e.g. HIGH -> "CRITICAL,HIGH").
func severitiesAtAndAbove(min v1alpha1.Severity) string {
	levels := make([]string, 0, len(severityOrder))
	for _, s := range severityOrder {
		levels = append(levels, string(s))
		if s == min {
			break
		}
	}
	return strings.Join(levels, ",")
}

// allScanResultsTerminal reports whether every ScanResult is Succeeded or Failed.
func allScanResultsTerminal(imageScan *v1alpha1.ImageScan) bool {
	for _, sr := range imageScan.Status.ScanResults {
		if sr.Phase != v1alpha1.Succeeded && sr.Phase != v1alpha1.Failed {
			return false
		}
	}
	return true
}
