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
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

// ImageScanReconciler reconciles a ImageScan object
type ImageScanReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.velin.dev,resources=imagescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.velin.dev,resources=imagescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.velin.dev,resources=imagescans/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ImageScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	var imageScan v1alpha1.ImageScan

	if err := r.Get(ctx, req.NamespacedName, &imageScan); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("ImageScan resource not found — probably deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to fetch ImageScan")
		return ctrl.Result{}, err
	}

	if isTerminal(&imageScan) {
		return ctrl.Result{}, nil
	}

	// I am experiencing 409 conflict. Check the Summary.md
	// for more details.
	statusBase := imageScan.DeepCopy()

	if !isInitialized(&imageScan) {
		if err := r.initializeScan(ctx, &imageScan); err != nil {
			return ctrl.Result{}, err
		}
		// Initialized the CR
		applyConditions(&imageScan, scanStateInitialized)
		return ctrl.Result{}, r.Status().Patch(ctx, &imageScan, client.MergeFrom(statusBase))

	}

	createErrors, err := r.createPendingJobs(ctx, &imageScan)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Jobs have been created or they are running
	applyConditions(&imageScan, scanStateRunning)

	jobList := &batchv1.JobList{}
	if err := r.List(ctx, jobList, client.InNamespace(namespace), client.MatchingLabels{"imagescan": imageScan.Name}); err != nil {
		return ctrl.Result{}, err
	}

	observeJobStatuses(ctx, &imageScan, jobList.Items)

	allDone := allScanResultsTerminal(&imageScan)
	if allDone {
		// Jobs have completed so determine the final state
		applyConditions(&imageScan, scanStateFinished)
	}

	if err := r.Status().Patch(ctx, &imageScan, client.MergeFrom(statusBase)); err != nil {
		return ctrl.Result{}, err
	}

	// Delete the jobs
	if allDone {
		propagation := metav1.DeletePropagationBackground // why is that?
		for i := range imageScan.Status.ScanResults {
			sr := &imageScan.Status.ScanResults[i]
			job := &batchv1.Job{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("scan-%s-%s", imageScan.Name, sr.ID[:8]),
					Namespace: namespace,
				},
			}
			if err := r.Delete(ctx, job, &client.DeleteOptions{PropagationPolicy: &propagation}); err != nil && !apierrors.IsNotFound(err) {
				logger.Error(err, "Failed to delete completed job", "id", sr.ID)
			}
		}
	}

	if len(createErrors) > 0 {
		return ctrl.Result{}, errors.Join(createErrors...)
	}

	return ctrl.Result{}, nil
}

// initializeScan discovers target pods, dedupes their images, and seeds
// status.scanResults with a deterministic ID per image. Runs exactly once
// per ImageScan (gated on status.phase == "" by the caller).
func (r *ImageScanReconciler) initializeScan(ctx context.Context, imageScan *v1alpha1.ImageScan) error {
	logger := logf.FromContext(ctx)

	nsSelector, err := metav1.LabelSelectorAsSelector(imageScan.Spec.NamespaceSelector)
	if err != nil {
		return err
	}

	var namespaceList corev1.NamespaceList
	if err := r.List(ctx, &namespaceList, client.MatchingLabelsSelector{Selector: nsSelector}); err != nil {
		return err
	}

	podsSelector, err := metav1.LabelSelectorAsSelector(imageScan.Spec.PodSelector)
	if err != nil {
		return err
	}

	imagesSet := map[string]struct{}{}
	for _, ns := range namespaceList.Items {
		var podsList corev1.PodList
		if err := r.List(ctx, &podsList, client.InNamespace(ns.Name), client.MatchingLabelsSelector{Selector: podsSelector}); err != nil {
			return err
		}
		for _, pod := range podsList.Items {
			for _, c := range pod.Spec.InitContainers {
				imagesSet[c.Image] = struct{}{}
			}
			for _, c := range pod.Spec.Containers {
				imagesSet[c.Image] = struct{}{}
			}
		}
	}

	images := make([]string, 0, len(imagesSet))
	for img := range imagesSet {
		images = append(images, img)
	}
	sort.Strings(images)

	scanResults := make([]v1alpha1.ScanResult, 0, len(images))
	for _, imgRef := range images {
		hasher := sha256.New()
		hasher.Write([]byte(string(imageScan.UID)))
		hasher.Write([]byte(imgRef))
		id := fmt.Sprintf("%x", hasher.Sum(nil))[:16]
		scanResults = append(scanResults, v1alpha1.ScanResult{
			ID:       id,
			ImageRef: imgRef,
			Phase:    v1alpha1.Pending,
		})
	}

	imageScan.Status.ScanResults = scanResults

	logger.Info("Initialized scan", "images", len(images))
	return nil
}

// createPendingJobs creates a Job for every ScanResult still in Pending and flips
// it to Running.
func (r *ImageScanReconciler) createPendingJobs(ctx context.Context, imageScan *v1alpha1.ImageScan) ([]error, error) {
	logger := logf.FromContext(ctx)
	var createErrors []error

	for i := range imageScan.Status.ScanResults {
		sr := &imageScan.Status.ScanResults[i]
		if sr.Phase != v1alpha1.Pending {
			continue
		}

		job := buildJob(imageScan, sr)
		if err := controllerutil.SetControllerReference(imageScan, job, r.Scheme); err != nil {
			return createErrors, err
		}

		existingJob := &batchv1.Job{}
		err := r.Get(ctx, client.ObjectKeyFromObject(job), existingJob)
		switch {
		case apierrors.IsNotFound(err):
			if cerr := r.Create(ctx, job); cerr != nil {
				logger.Error(cerr, "Failed to create job")
				createErrors = append(createErrors, cerr)
				continue
			}
			logger.Info("Created job", "name", sr.ImageRef)
		case err != nil:
			return createErrors, err
		}

		sr.Phase = v1alpha1.Running
		logger.Info("Job is running", "ID", sr.ID, "name", sr.ImageRef)
	}
	return createErrors, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ImageScan{}).
		Owns(&batchv1.Job{}).
		Named("imagescan").
		Complete(r)
}
