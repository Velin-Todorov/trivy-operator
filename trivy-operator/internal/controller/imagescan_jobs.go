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
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

const (
	namespace = "velin-todorov-system"
	claimName = "velin-todorov-scan-results"
)

// buildJob is a helper to create a scanning job for an image
func buildJob(imageScan *v1alpha1.ImageScan, scan *v1alpha1.ScanResult) *batchv1.Job {
	name := fmt.Sprintf("scan-%s-%s", imageScan.Name, scan.ID[:8])

	args := []string{
		"image",
		// to prevent pulling the vulnerability DB on every scan, I have created 1 pod that holds the vuln. DB,
		// so that every Job(client) uses it and doesn't spin its own, which reduces the scan times from minutes to seconds
		"--server", "http://velin-todorov-trivy-server.velin-todorov-system.svc:8080",
		"--format", "json",
		"--output", fmt.Sprintf("/data/%s.json", scan.ID),
	}

	if imageScan.Spec.MinimalSeverity != "" {
		args = append(args, "--severity", severitiesAtAndAbove(imageScan.Spec.MinimalSeverity))
	}

	args = append(args, scan.ImageRef)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"imagescan": imageScan.Name,
				"scan-id":   scan.ID,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr.To[int32](0),
			TTLSecondsAfterFinished: ptr.To[int32](300),
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				RestartPolicy: corev1.RestartPolicyNever,
				// this is the client
				Containers: []corev1.Container{
					{
						Name:  "trivy",
						Image: "aquasec/trivy:latest",
						Args:  args,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "results",
								MountPath: "/data",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "results",
						VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
								ClaimName: claimName,
							},
						},
					},
				},
			}},
		},
	}

}

// observeJobStatuses transitions each ScanResult.Phase based on its Job's runtime status.
func observeJobStatuses(ctx context.Context, imageScan *v1alpha1.ImageScan, jobs []batchv1.Job) {
	logger := logf.FromContext(ctx)
	for i := range imageScan.Status.ScanResults {
		sr := &imageScan.Status.ScanResults[i]
		jobName := fmt.Sprintf("scan-%s-%s", imageScan.Name, sr.ID[:8])

		for _, job := range jobs {
			if job.Name != jobName {
				continue
			}

			if job.Status.Active > 0 && sr.Phase != v1alpha1.Running {
				sr.Phase = v1alpha1.Running
			}
			if job.Status.Succeeded > 0 && sr.Phase != v1alpha1.Succeeded {
				sr.Phase = v1alpha1.Succeeded
				logger.Info("Job has finished", "ID", sr.ID, "name", sr.ImageRef)
			}
			if job.Status.Failed > 0 && sr.Phase != v1alpha1.Failed {
				sr.Phase = v1alpha1.Failed
				if len(job.Status.Conditions) > 0 {
					sr.Error = job.Status.Conditions[0].Message
				}
			}
		}
	}
}
