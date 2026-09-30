# melo-iac Core Engine

[![Go Version](https://img.shields.io/badge/go-1.27+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-AGPL3-green.svg)](LICENSE)

`melo-iac` is the core backend and Kubernetes operator for the **Melo Infrastructure-as-Code** GitOps platform. It brings declarative continuous reconciliation to Terraform by monitoring Git repositories and executing native Terraform plan/apply operations inside Kubernetes.

---

## Architecture Overview

The core engine consists of two main Go binaries running in the cluster:

1. **Kubernetes Controller (`controller-runtime`):**
   * Watches `TerraformApp` Custom Resource Definitions (CRDs).
   * Listens for reconciliation signals (e.g., commit hash changes or explicit timestamp annotations like `melo-iac.io/reconcile-requested-at`).
   * Uses `hashicorp/terraform-exec` to safely run `terraform init`, `plan`, and `apply`.
   * Extracts the Directed Acyclic Graph (DAG) from Terraform state/plan payloads and uploads the JSON payload to internal object storage (MinIO/S3).
   * Updates the `TerraformApp` `.status` subresource.

2. **REST API Server:**
   * Stateless Go API serving requests from the Python CLI (`melo-iac-cli`) and React GUI (`melo-iac-gui`).
   * Interfaces directly with the Kubernetes API server using `client-go` to read CRD status and patch metadata annotations to trigger manual syncs.
   * Fetches parsed DAG state from storage to serve interactive graph data to the frontend.

---

## Getting Started

### Prerequisites

* Go `1.27+`
* Access to a Kubernetes cluster (Kind, K3d, Minikube, or GKE/EKS)
* `kubectl` installed and configured
* Terraform CLI `1.16+` installed in the binary path

### Environment Variables

| Variable           | Description                                       | Default                      |
|:-------------------|:--------------------------------------------------|:-----------------------------|
| `KUBECONFIG`       | Path to your kubeconfig file                      | `~/.kube/config`             |
| `API_PORT`         | Port for the Go REST Server                       | `8080`                       |
| `STORAGE_ENDPOINT` | MinIO/S3 endpoint for storing graph JSON payloads | `minio.melo-system.svc:9000` |
| `STORAGE_BUCKET`   | Bucket name for storing graph artifacts           | `melo-graphs`                |

### Local Development

1. **Clone the repository:**
   ```bash
   git clone https://github.com/EdmilsonRodrigues/melo-iac.git
   cd melo-iac
   ```

2. **Run the REST Server locally:**
   ```bash
   go run cmd/server/main.go
   ```

3. **Run the Controller locally (against your dev cluster):**
   ```bash
   go run cmd/controller/main.go
   ```

---

## API Endpoints Summary

| Method | Path                                     | Description                                                                                                                  |
|:-------|:-----------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------|
| `POST` | `/api/v1/auth/login`                     | List all monitored `TerraformApp` resources                                                                                  |
| `POST` | `/api/v1/auth/logout`                    | Fetch status and plan outputs for a specific app                                                                             |
| `GET`  | `/api/v1/apps`                           | List all monitored `TerraformApp` resources                                                                                  |
| `GET`  | `/api/v1/apps/:name`                     | Fetch status and plan outputs for a specific app                                                                             |
| `POST` | `/api/v1/apps/:name/sync`                | Patch CRD annotation to trigger immediate sync                                                                               |
| `GET`  | `/api/v1/apps/:name/graph?postSync=bool` | Fetch extracted DAG nodes & edges for UI rendering. If postSync it would show it for the plan, else, it shows current state. |

---

## License

AGPL3 License. See [LICENSE](LICENSE) for details.
