#!/usr/bin/env bash

set +x
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly IMAGE_REPOSITORY="${1:?Image repository is required}"
readonly IMAGE_TAG="${2:?Image tag is required}"
readonly DOCKER_HUB_USERNAME="${3:?Docker Hub username is required}"
readonly IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
readonly PLATFORMS="${PLATFORMS:-linux/amd64}"

DOCKER_HUB_TOKEN=""
IFS= read -r DOCKER_HUB_TOKEN || true
[[ -n "${DOCKER_HUB_TOKEN}" ]] || {
  echo "Docker Hub token is required on stdin." >&2
  exit 1
}

case "${DOCKER_HUB_USERNAME}" in
  *[!a-zA-Z0-9_-]*) echo "Docker Hub username contains unsupported characters." >&2; exit 1 ;;
esac
case "${IMAGE_REPOSITORY}" in
  "${DOCKER_HUB_USERNAME}/"*) ;;
  *) echo "Image repository must be in the Docker Hub username namespace." >&2; exit 1 ;;
esac
case "${DOCKER_HUB_TOKEN}" in
  *[!a-zA-Z0-9_.-]*) echo "Docker Hub token contains unsupported characters." >&2; exit 1 ;;
esac
export DOCKER_HUB_USERNAME DOCKER_HUB_TOKEN

umask 077
DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG
trap 'rm -rf -- "${DOCKER_CONFIG}"' EXIT

cat > "${DOCKER_CONFIG}/docker-credential-centerauth" <<'HELPER'
#!/usr/bin/env bash
set +x
set -euo pipefail
case "${1:-}" in
  store) cat > /dev/null ;;
  get)
    SERVER_URL=""
    IFS= read -r SERVER_URL || true
    case "${SERVER_URL}" in
      https://index.docker.io/*|https://registry-1.docker.io|https://registry-1.docker.io/*|registry-1.docker.io|docker.io|https://docker.io|https://docker.io/*) ;;
      *) exit 1 ;;
    esac
    printf '{"Username":"%s","Secret":"%s"}\n' "${DOCKER_HUB_USERNAME}" "${DOCKER_HUB_TOKEN}"
    ;;
  erase) ;;
  *) exit 1 ;;
esac
HELPER

chmod 700 "${DOCKER_CONFIG}/docker-credential-centerauth"
export PATH="${DOCKER_CONFIG}:${PATH}"
printf '%s\n' '{"credsStore":"centerauth"}' > "${DOCKER_CONFIG}/config.json"

printf '%s' "${DOCKER_HUB_TOKEN}" |
  docker login --username "${DOCKER_HUB_USERNAME}" --password-stdin

docker buildx build \
  --platform "${PLATFORMS}" \
  --pull \
  --tag "${IMAGE}" \
  --push \
  "${SCRIPT_DIR}"

echo "Published ${IMAGE}"
