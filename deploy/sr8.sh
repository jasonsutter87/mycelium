#!/usr/bin/env bash
# Deploy Mycelium to SR8, the push-to-deploy way, same as Quarry: what you push is what runs.
#
#   deploy/sr8.sh [branch]      push, install the service and daily sync, clone your repos, restart
#
# Needs first: `gh auth login` on the server, and the app registered in Gatekeep's control plane (not clients.toml,
# which multi-tenant Gatekeep doesn't read for this). This script checks both and stops with the command if not.
# Your repo list starts from this Mac (`mycelium repos`) and is managed on the Repos page after that; the server keeps its own clones in ~/mycelium-repos.
set -euo pipefail
TARGET="jason@100.83.4.49"
BRANCH="${1:-$(git branch --show-current)}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

ssh "$TARGET" 'gh auth status >/dev/null 2>&1' || { echo "SR8 isn't signed in to GitHub. Run: ssh -t $TARGET gh auth login"; exit 1; }
curl -fs -m 10 -o /dev/null -G https://id.gatekeepauth.com/authorize --data-urlencode client_id=mycelium --data-urlencode redirect_uri=https://jason-server.taildf1d89.ts.net:4444/auth/callback \
  --data-urlencode response_type=code --data-urlencode scope=openid --data-urlencode state=x --data-urlencode nonce=x \
  --data-urlencode code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM --data-urlencode code_challenge_method=S256 || {
  echo "Gatekeep doesn't know this app yet. On SR8: docker exec gatekeep bun run src/tenancy/cli.ts app:set jason/production mycelium --name Mycelium --redirect https://jason-server.taildf1d89.ts.net:4444/auth/callback"; exit 1; }

ssh "$TARGET" 'mkdir -p ~/repos && [ -d ~/repos/mycelium.git ] || git init --quiet --bare ~/repos/mycelium.git'
git push --quiet "$TARGET:repos/mycelium.git" "$BRANCH:refs/heads/deploy" --force-with-lease=deploy 2>/dev/null || git push --quiet "$TARGET:repos/mycelium.git" "$BRANCH:refs/heads/deploy"
# First install only: after that, the list belongs to the dashboard's Repos page and a deploy must not undo it.
./bin/mycelium repos | ssh "$TARGET" 'mkdir -p ~/.config/mycelium; f=~/.config/mycelium/repos.txt; if [ -s "$f" ]; then cat >/dev/null; else cat > "$f"; fi'

ssh "$TARGET" 'bash -s' <<'REMOTE'
set -euo pipefail
[ -d ~/mycelium/.git ] || git clone --quiet --branch deploy ~/repos/mycelium.git ~/mycelium
cd ~/mycelium
git fetch --quiet origin deploy && git checkout --quiet -B deploy origin/deploy
export PATH="$HOME/.local/opt/node22/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
npm ci --omit=dev --no-audit --no-fund --silent
gh auth setup-git

# Build tools for verifying fixes, installed for this user only.
# pnpm stays on 10: your lockfiles are v9, and 12 no longer reads pnpm.overrides, which is how fixes are applied.
[ "$(pnpm --version 2>/dev/null | cut -d. -f1)" = 10 ] || npm install --silent --prefix ~/.local -g pnpm@10
command -v cargo >/dev/null || { curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path >/dev/null; }

mkdir -p ~/.config/systemd/user
cp deploy/mycelium.service deploy/sync.service deploy/sync.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --quiet mycelium.service sync.timer
systemctl --user restart mycelium.service
systemctl --user start sync.timer
tailscale serve --bg --https=4444 http://127.0.0.1:4700 >/dev/null
systemctl --user start --no-block sync.service
sleep 3
systemctl --user is-active mycelium.service
REMOTE
echo "Deployed. https://jason-server.taildf1d89.ts.net:4444 (tailnet devices, Gatekeep sign-in)."
echo "First clone is running in the background: ssh $TARGET journalctl --user -u sync -f"
