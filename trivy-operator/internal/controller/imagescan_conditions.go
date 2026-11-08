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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

const (
	ConditionTypeReady       = "Ready"
	ConditionTypeProgressing = "Progressing"

	ReasonInitialized        = "Initialized"
	ReasonScanningInProgress = "ScanningInProgress"
	ReasonAllScansFinished   = "AllScansFinished"
)

// scanState represents the state through which the CR moves
type scanState int

const (
	// scanStateInitialized means that the CR has just been initialized
	scanStateInitialized scanState = iota

	// scanStateRunning means that the image scanning jobs have been created and scanning is running
	scanStateRunning

	// scanStateFinished means that all the scanning jobs have finished.
	scanStateFinished
)

// isInitialized reports whether the controller has set up the ImageScan's
// initial state.
func isInitialized(imageScan *v1alpha1.ImageScan) bool {
	prog := meta.FindStatusCondition(imageScan.Status.Conditions, ConditionTypeProgressing)
	return prog != nil && prog.Status == metav1.ConditionTrue
}

// isTerminal reports whether the ImageScan has reached a terminal state.
func isTerminal(imageScan *v1alpha1.ImageScan) bool {
	ready := meta.FindStatusCondition(imageScan.Status.Conditions, ConditionTypeReady)
	return ready != nil && ready.Status == metav1.ConditionTrue
}

// applyConditions updates the status via the Conditions given the state the CR is in.
func applyConditions(imageScan *v1alpha1.ImageScan, state scanState) {
	ready := metav1.Condition{
		Type:               ConditionTypeReady,
		ObservedGeneration: imageScan.Generation,
	}
	progressing := metav1.Condition{
		Type:               ConditionTypeProgressing,
		ObservedGeneration: imageScan.Generation,
	}

	switch state {
	case scanStateInitialized:
		ready.Status = metav1.ConditionFalse
		ready.Reason = ReasonInitialized
		ready.Message = "ImageScan has been initialized"

		progressing.Status = metav1.ConditionTrue
		progressing.Reason = ReasonInitialized
		progressing.Message = "ImageScan has been initialized."

	case scanStateRunning:
		ready.Status = metav1.ConditionFalse
		ready.Reason = ReasonScanningInProgress
		ready.Message = "Image scans are in progress"

		progressing.Status = metav1.ConditionTrue
		progressing.Reason = ReasonScanningInProgress
		progressing.Message = "Image scans are in progress"

	case scanStateFinished:
		ready.Status = metav1.ConditionTrue
		ready.Reason = ReasonAllScansFinished
		ready.Message = "All image scans finished."

		progressing.Status = metav1.ConditionFalse
		progressing.Reason = ReasonAllScansFinished
		progressing.Message = "All image scans finished."
	}

	meta.SetStatusCondition(&imageScan.Status.Conditions, ready)
	meta.SetStatusCondition(&imageScan.Status.Conditions, progressing)
}
