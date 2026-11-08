## Увод
Съществуват програми от тип "security scanners", които при подаден target (container image, kubernetes cluster, computer program...) изпълняват набор от проверки за откриване на уязвимости.

Един такъв "scanner" е **Trivy**. В контекста на задачата се интересуваме единствено от способността му да извършва сканиране на [container images](https://en.wikipedia.org/wiki/Container_format).

В GitHub страницата на проекта (https://github.com/aquasecurity/trivy) може да намерите примери за изпълнение на scan върху image и документация за различните флагове и опции.

## Цел на задачата

Да се напише Kubernetes оператор на Go, който автоматизира security scanning на container images в cluster и предоставя лесен достъп до резултатите.

## Go Kubernetes Operator (стъпка 1)

Да се напише оператор на Go, който:
- Ще бъде инсталиран в Kubernetes cluster. Препоръчително е да се използва Kind, но и други опции като Minikube също са приемливи стига да отговарят на нуждите.
- Ще extend-не Kubernetes API с помощта на CRD (Custom Resouce Definition), т.е. ще инсталира дефиницията в клъстъра.
- Ще реагира на нови обекти от тип дефинирания custom resource.
- Ще валидира създаването на custom objects чрез помощта на `validating webhook`.
- Ще има за цел да изпълнява security сканиране при създаване на custom resource и да съхранява резултатите от сканирането в persistent storage.

Операторът ще се инсталира в Kubernetes клъстъра като `Deployment`. Важно е да се обърне внимание на това, че операторът ще има нужда от права да създава, модифицира и изтрива съответните ресурси (`Job`/`Pod`/`Service`/etc.).

Конкретни изисквания относно сканирането и работата на оператора:
- `CRD`-то да дефинира `cluster-scoped` ресурс с име `ImageScan`, който представлява заявка за изпълнение на security scan върху container images, използвани в `Pod`-ове в cluster-а. `CRD`-то трябва да описва:
  - Механизъм за таргетиране на `Namespace`-и чрез label selector
  - Механизъм за таргетиране на `Pod`-ове чрез label selector
  - Забележка: Операторът таргетира само `Pod`-ове, не и други ресурси
  - `ImageScan` ресурсът трябва да е immutable след създаването му

- При успешна валидация на обекта от тип `ImageScan`:
  - Намира всички `Pod` ресурси, които отговарят на условията от label selector-ите и извлича всички уникални image референции
  - Изпълнява Trivy scan върху всички уникални images чрез `Job` ресурс.
  - Резултатите от сканирането да се записват в JSON формат в persistent storage (напр. `PVC`)
  - Статусът на операцията да се записва в `ImageScan` ресурса, например когато нещо не сработи искаме да можем да го видим в `.status` [subresource](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#status-subresource)-a. 
  - За удобство ще искаме всеки scan да може да бъде идентифициран с уникално ID. Те също могат да бъдат записвани в `.status` subresource.

- При приключване на сканиране:
  - Съответните `Job` ресурси да се изтриват.

## Предоставяне на достъп до резултатите (стъпка 2)

Освен извършването на основната функционалност (сканиране), операторът трябва също да предоставя функционалност за лесното извличане на резултатите от сканирането.
За целта, операторът трябва да предоставя HTTP endpoints за достъп до scan резултатите. Резултатите трябва да са в machine-readable формат (напр. JSON):
- `GET /scans/{id}` - връща резултата от конкретно сканиране по неговото ID
- `GET /scans` - връща списък със scan резултати, с опция за филтриране по image prefix

Този endpoint може да бъде реализиран като част от оператора или като отделен компонент, който използва същия persistent storage (volume) за достъп до резултатите. В случая на отделния компонент, той може да бъде стартиран като допълнителен контейнер в същия `Pod` на оператора, който изпълнява сканирането.

Ще е нужен `Service` ресурс, който да expose-не този endpoint в cluster-а, за да може администраторите да го достъпват. За по-лесно нека service-ът е от тип `ClusterIP`. Връзка към него може да се тества с командата `kubectl port-forward service/<nameofservice>`.

### Примерен сценарий за използване:
1. Администратор създава `ImageScan` ресурс, който таргетира всички `Pod`-ове с label `app=web` в `Namespace`-и с label `env=production`.
2. Validating webhook-ът проверява дали заявката е валидна, като валидира че има ресурси (`Pod`-ове), които биха били таргетирани от комбинацията от namespace и pod label selectors.
3. Операторът открива всички `Pod`-ове с този label, извлича уникалните container images и изпълнява Trivy scan върху тях.
4. Резултатите от сканирането се записват в JSON файлове в `PVC`.
5. Администраторът проверява `.status` полето на създадения `ImageScan` ресурс и извлича ID-тата на сканиранията.
6. Администраторът изпълнява `kubectl port-forward service/scan-results-service 8080:80`, извиква `GET http://localhost:8080/scans/{id}` и получава резултата от конкретното сканиране.
7. Администраторът може да прегледа резултатите и да предприеме действия, ако бъдат открити уязвимости.

### Бонус!
- Pagination (limit и offset) за `GET /scans` endpoint-а
- Възможност за сканиране на частни registry-та, като се предоставят credentials чрез Kubernetes `Secret`.
- Да се разшири дефиницията на `CRD`-то, така че да поддържа `--severity` флагът на Trivy, който позволява да се зададе минималното ниво на сериозност на уязвимостите, които да бъдат включени в резултатите от сканирането. 

### Документация

- [Trivy Documentation](https://trivy.dev/docs/latest/guide/)
- [Operator Pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
- [CRDs](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
- [Pod](https://kubernetes.io/docs/concepts/workloads/pods/)
- [Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
- [Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/jobs-run-to-completion/)
- [Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
- [Persistent Volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)
- [Persistent Volume Claims](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#persistentvolumeclaims)
- [Services](https://kubernetes.io/docs/concepts/services-networking/service/)
- [Validating Webhooks](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- [kubectl Cheat Sheet](https://kubernetes.io/docs/reference/kubectl/quick-reference/)

### Библиотеки и инструменти (не е изчерпателен списък), които ще бъдат от полза при имплементацията на оператора:
- [client-go](https://github.com/kubernetes/client-go/)
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)
- [kubebuilder](https://book.kubebuilder.io/)

## Пояснения

Части от задачата подлежат на интерпретация!
Основната цел е да се обяснят и аргументират взетите решения за конкретната имплементация.
