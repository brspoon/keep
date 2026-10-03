#!/bin/sh
# Disposable, offline web/worker startup and persistent-volume check.
set -eu
smoke_image=${1:-keep-ci}
smoke_web=keep-smoke-web-$$
smoke_worker=keep-smoke-worker-$$
smoke_volume=keep-smoke-data-$$
cleanup() {
  docker rm -f "$smoke_web" "$smoke_worker" >/dev/null 2>&1 || true
  docker volume rm "$smoke_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
docker volume create "$smoke_volume" >/dev/null
start() {
  smoke_name=$1
  shift
  docker run -d --name "$smoke_name" --network none --read-only --tmpfs /tmp \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -v "$smoke_volume:/app/data" \
    -e FLASK_SECRET_KEY=synthetic-container-smoke-secret-0000000000 \
    -e PLEX_OWNER_ID=7 "$smoke_image" "$@" >/dev/null
}
ready() {
  smoke_attempt=0
  until docker exec "$smoke_web" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health',timeout=2)" >/dev/null 2>&1; do
    smoke_attempt=$((smoke_attempt + 1))
    test "$smoke_attempt" -lt 30 || return 1
    sleep 1
  done
}
assert_no_control_server_error() {
  smoke_logs=$(docker logs "$smoke_web" 2>&1)
  case "$smoke_logs" in
    *"Control server error"*)
      printf '%s\n' "$smoke_logs" >&2
      return 1
      ;;
  esac
}
start "$smoke_web"
ready
start "$smoke_worker" python -u app.py --digest-worker
docker exec "$smoke_web" python -c "import sqlite3; db=sqlite3.connect('/app/data/keep.sqlite3'); db.execute(\"INSERT INTO keep_attribution(collection_id,media_id,user_id,username) VALUES('1','smoke','7','Test')\"); db.commit()"
docker restart "$smoke_web" "$smoke_worker" >/dev/null
ready
docker exec "$smoke_web" python -c "import os,sqlite3; assert os.getuid()==10001; db=sqlite3.connect('/app/data/keep.sqlite3'); assert db.execute(\"SELECT media_id FROM keep_attribution WHERE media_id='smoke'\").fetchone(); assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'"
smoke_attempt=0
until docker exec "$smoke_worker" python -c "import os,time; p='/app/data/digest-worker.heartbeat'; assert time.time()-os.path.getmtime(p)<60" >/dev/null 2>&1; do
  smoke_attempt=$((smoke_attempt + 1))
  test "$smoke_attempt" -lt 30 || exit 1
  sleep 1
done
assert_no_control_server_error
printf '%s\n' 'Offline web/worker startup, restart and durable-data smoke test passed.'
