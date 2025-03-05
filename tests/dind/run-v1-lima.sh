#!/bin/bash
set -e

# Dockerソケットパスを見つける関数
find_docker_socket() {
  for uid in 1000 1001 $(id -u); do
    socket_path="/run/user/${uid}/docker.sock"
    if [ -S "$socket_path" ]; then
      echo "$socket_path"
      return 0
    fi
  done
  
  # Lima環境でのソケットパス
  if [ -S "${HOME}/.lima/default/sock/docker.sock" ]; then
    echo "${HOME}/.lima/default/sock/docker.sock"
    return 0
  fi
  
  echo "/var/run/docker.sock"  # デフォルト
  return 1
}

# Dockerソケットを設定
DOCKER_SOCKET=$(find_docker_socket)
export DOCKER_HOST="unix://${DOCKER_SOCKET}"
echo "Using Docker socket: ${DOCKER_HOST}"

# テスト環境の設定
ROOT=$(git rev-parse --show-toplevel)
YOUKI_BIN=$(find "$ROOT" -name "youki" -type f -executable | head -1)

echo "Using youki binary: ${YOUKI_BIN}"

# 基本的なDocker実行オプション
DOCKER_OPTS="--privileged -dq \
  --name youki-test-dind \
  -v ${YOUKI_BIN}:/usr/bin/youki:ro \
  -v $ROOT/tests/dind/daemon.json:/etc/docker/daemon.json"

# Lima環境検出
if [ -d "/run/lima" ] || [ -d "$HOME/.lima" ]; then
  echo "Lima environment detected"
  DOCKER_OPTS="$DOCKER_OPTS --network=lima:user-v2"
fi

# Dockerコンテナを起動
echo "Starting Docker-in-Docker container..."
eval "docker run $DOCKER_OPTS docker:dind > /dev/null"

trap "docker rm -f youki-test-dind > /dev/null" EXIT

# Dockerデーモンの起動を待機
echo "Waiting for Docker daemon to start..."
timeout 30s \
  grep -q -m1 "/var/run/docker.sock" \
    <(docker logs -f youki-test-dind 2>&1)

# 環境情報の収集
echo "Container environment information:"
docker exec -i youki-test-dind cat /etc/os-release
docker exec -i youki-test-dind uname -a

# デバッグ情報の収集
echo "Debug information:"
docker exec -i youki-test-dind ls -la /usr/bin/youki
docker exec -i youki-test-dind cat /etc/docker/daemon.json

# youkiのデバッグ情報
echo "Trying youki in debug mode:"
docker exec -i youki-test-dind /usr/bin/youki --version || echo "youki version failed"

# 依存関係の確認
echo "Checking dynamic dependencies:"
docker exec -i youki-test-dind sh -c "ldd /usr/bin/youki || echo 'ldd not found or not applicable'"

# strace（あれば）での診断
echo "Tracing youki execution (if strace available):"
docker exec -i youki-test-dind sh -c "strace -f /usr/bin/youki --version 2>&1 || echo 'strace not available'"

# Docker ログの確認
echo "Docker logs:"
docker exec -i youki-test-dind sh -c "cat /var/log/docker.log 2>/dev/null || journalctl -u docker --no-pager 2>/dev/null || echo 'Docker logs not found'"

# テスト実行
echo "Running test with youki runtime:"
docker exec -i youki-test-dind docker run -q --runtime=youki hello-world || echo "Test failed with exit code $?"
