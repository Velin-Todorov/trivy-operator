/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package v1alpha1

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	securityv1alpha1 "github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

var _ = Describe("ImageScan Webhook", func() {
	var validator ImageScanCustomValidator

	BeforeEach(func() {
		// ValidateUpdate is a pure function over the two specs; the embedded
		// client is unused for this code path, so a zero-value validator is fine.
		validator = ImageScanCustomValidator{}
	})

	Context("ValidateUpdate", func() {
		It("rejects spec changes after creation", func() {
			old := &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{Name: "scan-immutability-test"},
				Spec: securityv1alpha1.ImageScanSpec{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "production"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
			}
			updated := old.DeepCopy()
			updated.Spec.PodSelector.MatchLabels["app"] = "api"

			warnings, err := validator.ValidateUpdate(ctx, old, updated)
			Expect(warnings).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("immutable"))
		})

		It("admits no-op updates that leave the spec unchanged", func() {
			old := &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "scan-noop-test",
					Labels: map[string]string{"foo": "bar"},
				},
				Spec: securityv1alpha1.ImageScanSpec{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "production"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
			}

			updated := old.DeepCopy()
			updated.Labels["foo"] = "baz"

			warnings, err := validator.ValidateUpdate(ctx, old, updated)
			Expect(warnings).To(BeNil())
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("ValidateCreate", func() {
		var (
			targetNamespaceName string
			obj                 *securityv1alpha1.ImageScan
		)

		BeforeEach(func() {
			validator = ImageScanCustomValidator{Client: k8sClient}
			targetNamespaceName = fmt.Sprintf("vc-target-%s", rand.String(5))
			obj = &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("scan-%s", rand.String(5))},
				Spec: securityv1alpha1.ImageScanSpec{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"kubernetes.io/metadata.name": targetNamespaceName},
					},
					PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
			}
		})

		It("rejects when NamespaceSelector is nil", func() {
			obj.Spec.NamespaceSelector = nil

			warnings, err := validator.ValidateCreate(ctx, obj)
			Expect(warnings).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Missing namespace selector"))
		})

		It("rejects when PodSelector is nil", func() {
			obj.Spec.PodSelector = nil

			warnings, err := validator.ValidateCreate(ctx, obj)
			Expect(warnings).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Missing pod selector"))
		})

		It("rejects when no namespaces match the selector", func() {
			warnings, err := validator.ValidateCreate(ctx, obj)
			Expect(warnings).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("No namespaces exist"))
		})

		It("rejects when namespaces match but no pods match", func() {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: targetNamespaceName},
			})).To(Succeed())

			warnings, err := validator.ValidateCreate(ctx, obj)
			Expect(warnings).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no pods match"))
		})

		It("admits when both selectors match real resources", func() {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: targetNamespaceName},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "web-pod",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: "nginx:1.25"}},
				},
			})).To(Succeed())

			warnings, err := validator.ValidateCreate(ctx, obj)
			Expect(warnings).To(BeNil())
			Expect(err).NotTo(HaveOccurred())
		})
	})
})
