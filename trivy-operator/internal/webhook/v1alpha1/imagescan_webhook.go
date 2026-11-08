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
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var imagescanlog = logf.Log.WithName("imagescan-resource")

// SetupImageScanWebhookWithManager registers the webhook for ImageScan in the manager.
func SetupImageScanWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &securityv1alpha1.ImageScan{}).
		WithValidator(&ImageScanCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-security-velin-dev-v1alpha1-imagescan,mutating=false,failurePolicy=fail,sideEffects=None,groups=security.velin.dev,resources=imagescans,verbs=create;update,versions=v1alpha1,name=vimagescan-v1alpha1.kb.io,admissionReviewVersions=v1

// ImageScanCustomValidator struct is responsible for validating the ImageScan resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ImageScanCustomValidator struct {
	client.Client
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ImageScan.
func (v *ImageScanCustomValidator) ValidateCreate(ctx context.Context, obj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon creation", "name", obj.GetName())

	if err := validateNamespace(obj.Spec.NamespaceSelector); err != nil {
		return nil, err
	}

	if err := validatePodSelector(obj.Spec.PodSelector); err != nil {
		return nil, err
	}

	nsSelector, err := metav1.LabelSelectorAsSelector(obj.Spec.NamespaceSelector)
	if err != nil {
		return nil, err
	}

	var namespaceList corev1.NamespaceList
	if err := v.List(ctx, &namespaceList, client.MatchingLabelsSelector{Selector: nsSelector}); err != nil {
		return nil, err
	}

	if len(namespaceList.Items) == 0 {
		return nil, field.Invalid(
			field.NewPath("spec").Child("namespaceSelector"),
			obj.Spec.NamespaceSelector,
			"No namespaces exist for the given labels",
		)
	}

	podsSelector, err := metav1.LabelSelectorAsSelector(obj.Spec.PodSelector)
	if err != nil {
		return nil, err
	}

	totalPods := 0

	for _, ns := range namespaceList.Items {
		var podsList corev1.PodList
		if err := v.List(ctx, &podsList, client.InNamespace(ns.Name), client.MatchingLabelsSelector{Selector: podsSelector}); err != nil {
			return nil, err
		}
		totalPods += len(podsList.Items)
	}

	if totalPods == 0 {
		return nil, field.Invalid(
			field.NewPath("spec").Child("podSelector"),
			obj.Spec.PodSelector,
			"no pods match the combined namespaceSelector and podSelector",
		)
	}

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ImageScan.
func (v *ImageScanCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon update", "name", newObj.GetName())
	if !reflect.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, fmt.Errorf("ImageScan spec is immutable after creation")
	}

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ImageScan.
func (v *ImageScanCustomValidator) ValidateDelete(_ context.Context, obj *securityv1alpha1.ImageScan) (admission.Warnings, error) {
	imagescanlog.Info("Validation for ImageScan upon deletion", "name", obj.GetName())
	return nil, nil
}

func validateNamespace(nsSelector *metav1.LabelSelector) *field.Error {
	if nsSelector == nil {
		return field.Invalid(
			field.NewPath("spec").Child("namespaceSelector"),
			nsSelector,
			"Missing namespace selector",
		)
	}
	return nil
}

func validatePodSelector(podSelector *metav1.LabelSelector) *field.Error {
	if podSelector == nil {
		return field.Invalid(
			field.NewPath("spec").Child("podSelector"),
			podSelector,
			"Missing pod selector",
		)
	}
	return nil
}
