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

# デバッグ用のボリュームマウント追加
DOCKER_OPTS="$DOCKER_OPTS -v /tmp:/host-tmp"

# Dockerコンテナを起動
echo "Starting Docker-in-Docker container..."
eval "docker run $DOCKER_OPTS docker:dind > /dev/null"

trap "docker rm -f youki-test-dind > /dev/null" EXIT

# Dockerデーモンの起動を待機
echo "Waiting for Docker daemon to start..."
timeout 30s \
  grep -q -m1 "/var/run/docker.sock" \
    <(docker logs -f youki-test-dind 2>&1)

# デバッグ用にログ設定を変更
docker exec -i youki-test-dind sh -c "mkdir -p /etc/youki"
docker exec -i youki-test-dind sh -c "echo -e '[log]\nlevel = \"debug\"\nfile = \"/host-tmp/youki-debug.log\"' > /etc/youki/config.toml"

# youkiが存在することを確認
echo "Debug information:"
docker exec -i youki-test-dind ls -la /usr/bin/youki
docker exec -i youki-test-dind cat /etc/docker/daemon.json
docker exec -i youki-test-dind sh -c "ls -la /etc/youki || echo 'No config dir'"
docker exec -i youki-test-dind sh -c "cat /etc/youki/config.toml || echo 'No config file'"

# テスト実行（エラーになることを許容）
echo "Running test with youki runtime (errors expected):"
docker exec -i youki-test-dind docker run -q --runtime=youki hello-world || echo "Test failed as expected with exit code $?"

# ログを収集
echo "Collecting logs:"
docker exec -i youki-test-dind sh -c "cat /host-tmp/youki-debug.log || echo 'No log file found'"
docker exec -i youki-test-dind sh -c "cat /var/log/docker.log 2>/dev/null || journalctl -u docker --no-pager 2>/dev/null || echo 'Docker logs not found'"
