# K8s Operator Makefile
# For building and deploying the GM-KMS Kubernetes Operator

.PHONY: all build test clean deploy install uninstall

# Image URL to use; also set in config/manager/manager.yaml
IMAGE ?= ghcr.io/gm-engineers/kms-operator
VERSION ?= latest

# Build the operator
build:
	go build -o bin/manager main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -rf bin/

# Build Docker image
docker-build:
	docker build -t $(IMAGE):$(VERSION) .

# Push Docker image
docker-push:
	docker push $(IMAGE):$(VERSION)

# Install CRD to the cluster
install:
	kubectl apply -f config/crd/bases/kms.example.com_kmskeys.yaml

# Uninstall CRD from the cluster
uninstall:
	kubectl delete -f config/crd/bases/kms.example.com_kmskeys.yaml

# Deploy operator to the cluster
deploy:
	kubectl apply -f config/rbac/role.yaml
	kubectl apply -f config/manager/manager.yaml

# Delete operator from the cluster
undeploy:
	kubectl delete -f config/manager/manager.yaml
	kubectl delete -f config/rbac/role.yaml

# Generate manifests (requires controller-gen)
manifests:
	controller-gen crd:crdVersions=v1 rbac:roleName=kms-operator-role paths="./..." output:crd:artifacts:config=config/crd/bases

# Generate code (requires controller-gen)
generate:
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Run against the configured Kubernetes cluster
run:
	go run ./main.go --kubeconfig=$(KUBECONFIG) --kms-server-url=$(KMS_SERVER_URL)

# Download dependencies
deps:
	go mod tidy
	go mod download
