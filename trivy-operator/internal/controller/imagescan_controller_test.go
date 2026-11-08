/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	securityv1alpha1 "github.com/Velin-Todorov/trivy-operator/api/v1alpha1"
)

var _ = Describe("ImageScan Controller", func() {
	Context("When reconciling a fresh ImageScan", func() {
		const (
			targetPodName  = "target-pod"
			testNginxImage = "nginx:1.25"
			testRedisImage = "redis:7"
		)

		ctx := context.Background()
		var (
			targetNamespaceName string
			imageScanName       string
		)

		BeforeEach(func() {
			targetNamespaceName = fmt.Sprintf("scan-target-%s", rand.String(5))
			imageScanName = fmt.Sprintf("scan-%s", rand.String(5))

			By("creating a labeled target namespace and pod")
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   targetNamespaceName,
					Labels: map[string]string{"env": "test"},
				},
			})).To(Succeed())

			By("creating the ImageScan resource")
			Expect(k8sClient.Create(ctx, &securityv1alpha1.ImageScan{
				ObjectMeta: metav1.ObjectMeta{Name: imageScanName},
				Spec: securityv1alpha1.ImageScanSpec{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": targetNamespaceName}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				},
			})).To(Succeed())
		})

		AfterEach(func() {
			By("removing test resources")
			_ = k8sClient.Delete(ctx, &securityv1alpha1.ImageScan{ObjectMeta: metav1.ObjectMeta{Name: imageScanName}})
			_ = k8sClient.Delete(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: targetPodName, Namespace: targetNamespaceName}})
			_ = k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: targetNamespaceName}})

			err := k8sClient.DeleteAllOf(ctx, &batchv1.Job{},
				client.InNamespace("velin-todorov-system"),
				client.MatchingLabels{"imagescan": imageScanName})
			fmt.Printf("AfterEach DeleteAllOf err: %v\n", err)
		})

		It("populates status.scanResults from images of matching pods", func() {
			By("running a single Reconcile pass")

			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      targetPodName,
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testNginxImage}},
				},
			})).To(Succeed())

			reconciler := &ImageScanReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("verifying the ImageScan status")
			fetched := &securityv1alpha1.ImageScan{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())

			Expect(fetched.Status.ScanResults).To(HaveLen(1))
			Expect(fetched.Status.ScanResults[0].ImageRef).To(Equal(testNginxImage))
			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Pending))
			Expect(fetched.Status.ScanResults[0].ID).To(HaveLen(16))

			progressing := meta.FindStatusCondition(fetched.Status.Conditions, ConditionTypeProgressing)
			Expect(progressing).NotTo(BeNil())
			Expect(progressing.Status).To(Equal(metav1.ConditionTrue))
			Expect(progressing.Reason).To(Equal(ReasonInitialized))
		})

		It("deduplicates images across pods", func() {
			// Create 2 pods with nginx and 1 pod with redis
			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testNginxImage}},
				},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod2",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testNginxImage}},
				},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testRedisImage}},
				},
			})).To(Succeed())

			reconciler := &ImageScanReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})

			Expect(err).NotTo(HaveOccurred())

			fetched := &securityv1alpha1.ImageScan{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())
			Expect(fetched.Status.ScanResults).To(HaveLen(2))
			Expect(fetched.Status.ScanResults[0].ImageRef).To(Equal(testNginxImage))
			Expect(fetched.Status.ScanResults[1].ImageRef).To(Equal(testRedisImage))

			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Pending))
			Expect(fetched.Status.ScanResults[1].Phase).To(Equal(securityv1alpha1.Pending))

			progressing := meta.FindStatusCondition(fetched.Status.Conditions, ConditionTypeProgressing)
			Expect(progressing).NotTo(BeNil())
			Expect(progressing.Status).To(Equal(metav1.ConditionTrue))
			Expect(progressing.Reason).To(Equal(ReasonInitialized))
		})

		It("transitions pending jobs to running and Jobs are created", func() {
			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testRedisImage}},
				},
			})).To(Succeed())

			reconciler := &ImageScanReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			fetched := &securityv1alpha1.ImageScan{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())
			Expect(fetched.Status.ScanResults).To(HaveLen(1))
			Expect(fetched.Status.ScanResults[0].ImageRef).To(Equal(testRedisImage))
			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Pending))

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			jobs := &batchv1.JobList{}
			Expect(k8sClient.List(ctx, jobs,
				client.InNamespace("velin-todorov-system"),
				client.MatchingLabels{"imagescan": imageScanName})).To(Succeed())

			Expect(jobs.Items).To(HaveLen(1))
			Expect(jobs.Items[0].Spec.Template.Spec.Containers[0].Image).To(ContainSubstring("trivy"))

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())
			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Running))
		})

		It("completes all jobs and jobs are deleted after completion", func() {
			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod3",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testRedisImage}},
				},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod4",
					Namespace: targetNamespaceName,
					Labels:    map[string]string{"app": "web"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "main", Image: testNginxImage}},
				},
			})).To(Succeed())

			reconciler := &ImageScanReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			fetched := &securityv1alpha1.ImageScan{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())
			Expect(fetched.Status.ScanResults).To(HaveLen(2))

			Expect(fetched.Status.ScanResults[0].ImageRef).To(Equal(testNginxImage))
			Expect(fetched.Status.ScanResults[1].ImageRef).To(Equal(testRedisImage))

			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Pending))
			Expect(fetched.Status.ScanResults[1].Phase).To(Equal(securityv1alpha1.Pending))

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			jobs := &batchv1.JobList{}
			Expect(k8sClient.List(ctx, jobs,
				client.InNamespace("velin-todorov-system"),
				client.MatchingLabels{"imagescan": imageScanName})).To(Succeed())

			Expect(jobs.Items).To(HaveLen(2))

			job1 := &batchv1.Job{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "scan-" + imageScanName + "-" + fetched.Status.ScanResults[0].ID[:8],
				Namespace: "velin-todorov-system",
			}, job1)).To(Succeed())

			job2 := &batchv1.Job{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "scan-" + imageScanName + "-" + fetched.Status.ScanResults[1].ID[:8],
				Namespace: "velin-todorov-system",
			}, job2)).To(Succeed())

			job1.Status.Succeeded = 1
			job2.Status.Succeeded = 1

			Expect(k8sClient.Status().Update(ctx, job1)).To(Succeed())
			Expect(k8sClient.Status().Update(ctx, job2)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: imageScanName},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: imageScanName}, fetched)).To(Succeed())
			Expect(fetched.Status.ScanResults[0].Phase).To(Equal(securityv1alpha1.Succeeded))
			Expect(fetched.Status.ScanResults[1].Phase).To(Equal(securityv1alpha1.Succeeded))

			progressing := meta.FindStatusCondition(fetched.Status.Conditions, ConditionTypeProgressing)
			Expect(progressing).NotTo(BeNil())
			Expect(progressing.Status).To(Equal(metav1.ConditionFalse))
			Expect(progressing.Reason).To(Equal(ReasonAllScansFinished))

			ready := meta.FindStatusCondition(fetched.Status.Conditions, ConditionTypeReady)
			Expect(ready).NotTo(BeNil())
			Expect(ready.Status).To(Equal(metav1.ConditionTrue))
			Expect(ready.Reason).To(Equal(ReasonAllScansFinished))

		})
	})
})
