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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Severity desrcibes trivy severity
type Severity string

// Definitions of trivy severity
const (
	LOW      Severity = "LOW"
	MEDIUM   Severity = "MEDIUM"
	HIGH     Severity = "HIGH"
	CRITICAL Severity = "CRITICAL"
	UNKNOWN  Severity = "UNKNOWN"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageScanSpec defines the desired state of ImageScan
type ImageScanSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// The following markers will use OpenAPI v3 schema to validate the value
	// More info: https://book.kubebuilder.io/reference/markers/crd-validation.html

	// +kubebuilder:validation:Required
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`
	// +kubebuilder:validation:Required
	PodSelector *metav1.LabelSelector `json:"podSelector"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=CRITICAL;HIGH;MEDIUM;LOW;UNKNOWN
	MinimalSeverity Severity `json:"minimalSeverity,omitempty"`
}

// ScanPhase describes phases for a scan.
type ScanPhase string

const (
	Pending   ScanPhase = "Pending"
	Running   ScanPhase = "Running"
	Succeeded ScanPhase = "Succeeded"
	Failed    ScanPhase = "Failed"
)

// ScanResult identifies an individiaul scan of an image
type ScanResult struct {
	ID       string `json:"id"`
	ImageRef string `json:"imageRef"`
	// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
	Phase ScanPhase `json:"phase,omitempty"`
	Error string    `json:"error,omitempty"`
}

// ImageScanStatus defines the observed state of ImageScan.
type ImageScanStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +listType=map
	// +listMapKey=id
	// +optional
	ScanResults []ScanResult `json:"scanResults,omitempty"`
	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the ImageScan resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ImageScan is the Schema for the imagescans API
type ImageScan struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ImageScan
	// +required
	Spec ImageScanSpec `json:"spec"`

	// status defines the observed state of ImageScan
	// +optional
	Status ImageScanStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ImageScanList contains a list of ImageScan
type ImageScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ImageScan `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageScan{}, &ImageScanList{})
}
