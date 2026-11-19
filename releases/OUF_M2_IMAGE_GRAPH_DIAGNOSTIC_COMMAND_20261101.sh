(
  set -euo pipefail
  umask 077
  ouf_image_graph_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_image_graph_tmp"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 \
    --tlsv1.2 --connect-timeout 10 --max-time 30 --retry 0 --max-filesize 16384 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/71a1d6710767a2e0572f5ea9de19db35d333873e/scripts/launch-m2-retained-image-graph-20261101.sh \
    --output "$ouf_image_graph_tmp/run.sh"
  printf '%s  %s\n' 36037795acf4292935c3f973a4f5602bd60dc0e275b17796c301dccb3692a737 "$ouf_image_graph_tmp/run.sh" | sha256sum --check --strict
  sudo -v
  set +e
  bash "$ouf_image_graph_tmp/run.sh"
  ouf_image_graph_exit=$?
  set -e
  printf 'ImageGraphDiagnosticExit=%s\n' "$ouf_image_graph_exit"
  exit "$ouf_image_graph_exit"
)
