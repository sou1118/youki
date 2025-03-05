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
  -v ${YOUKI_BIN}:/usr/bin/youki:ro"

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

# ラッパースクリプトを作成
echo "Creating youki wrapper script..."
docker exec -i youki-test-dind sh -c "cat > /usr/bin/youki-wrapper << 'EOF'
#!/bin/sh
set -e

# ログディレクトリを作成
mkdir -p /tmp/youki-logs

# 実行コマンドをログに記録
echo \"[\$(date)] Running youki with args: \$@\" > /tmp/youki-logs/wrapper.log
echo \"Environment:\" >> /tmp/youki-logs/wrapper.log
env >> /tmp/youki-logs/wrapper.log

# youkiを実行し、出力をキャプチャ
/usr/bin/youki \"\$@\" > /tmp/youki-logs/stdout.log 2> /tmp/youki-logs/stderr.log || {
  EXIT_CODE=\$?
  echo \"youki failed with exit code \$EXIT_CODE\" >> /tmp/youki-logs/wrapper.log
  exit \$EXIT_CODE
}
EOF"

# 実行権限を付与
docker exec -i youki-test-dind chmod +x /usr/bin/youki-wrapper

# daemon.jsonを作成
echo "Creating daemon.json with youki-wrapper..."
docker exec -i youki-test-dind sh -c "cat > /etc/docker/daemon.json << 'EOF'
{
  \"runtimes\": {
    \"youki\": {
      \"path\": \"/usr/bin/youki-wrapper\"
    }
  }
}
EOF"

# 必要なディレクトリを作成
docker exec -i youki-test-dind mkdir -p /tmp/youki-logs

# Dockerデーモンを再起動
echo "Restarting Docker daemon..."
docker exec -i youki-test-dind kill -SIGHUP 1
sleep 5

# 設定情報の確認
echo "Configuration:"
docker exec -i youki-test-dind cat /etc/docker/daemon.json
docker exec -i youki-test-dind ls -la /usr/bin/youki /usr/bin/youki-wrapper

# youkiバイナリのテスト
echo "Testing youki binary directly:"
docker exec -i youki-test-dind /usr/bin/youki --version || echo "youki version test failed with exit code $?"

# シンプルなテストケースで手動テスト
echo "Manual container creation test:"
docker exec -i youki-test-dind sh -c "mkdir -p /tmp/test-container"
docker exec -i youki-test-dind sh -c "cd /tmp/test-container && /usr/bin/youki create test-container" || echo "Manual test failed with exit code $?"

# テスト実行
echo "Running test with youki runtime:"
docker exec -i youki-test-dind docker run -q --runtime=youki hello-world || echo "Test failed with exit code $?"

# ログの収集
echo "Wrapper logs:"
docker exec -i youki-test-dind cat /tmp/youki-logs/wrapper.log || echo "No wrapper logs found"
echo "Stdout logs:"
docker exec -i youki-test-dind cat /tmp/youki-logs/stdout.log || echo "No stdout logs found"
echo "Stderr logs:"
docker exec -i youki-test-dind cat /tmp/youki-logs/stderr.log || echo "No stderr logs found"
