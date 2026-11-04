#!/usr/bin/env bash
# Deploy Mycelium to SR8, the push-to-deploy way, same as Quarry: what you push is what runs.
#
#   deploy/sr8.sh [branch]      push, install the service and daily sync, clone your repos, restart
#
# Needs on the server first: `gh auth login`, and a [clients.mycelium] entry in Gatekeep's clients.toml with
# redirect URI https://jason-server.taildf1d89.ts.net:4444/auth/callback. This script checks and stops if not.
# Your repo list comes from this Mac (`mycelium repos`); the server keeps its own clones in ~/mycelium-repos.
set -euo pipefail
TARGET="jason@100.83.4.49"
BRANCH="${1:-$(git branch --show-current)}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

ssh "$TARGET" 'gh auth status >/dev/null 2>&1' || { echo "SR8 isn't signed in to GitHub. Run: ssh -t $TARGET gh auth login"; exit 1; }
ssh "$TARGET" 'grep -q "^\[clients\.mycelium\]" ~/gatekeep/clients.toml' || { echo "Gatekeep doesn't know this app yet: add [clients.mycelium] to ~/gatekeep/clients.toml on SR8, then restart Gatekeep."; exit 1; }

ssh "$TARGET" 'mkdir -p ~/repos && [ -d ~/repos/mycelium.git ] || git init --quiet --bare ~/repos/mycelium.git'
git push --quiet "$TARGET:repos/mycelium.git" "$BRANCH:refs/heads/deploy" --force-with-lease=deploy 2>/dev/null || git push --quiet "$TARGET:repos/mycelium.git" "$BRANCH:refs/heads/deploy"
./bin/mycelium repos | ssh "$TARGET" 'mkdir -p ~/.config/mycelium && cat > ~/.config/mycelium/repos.txt'

ssh "$TARGET" 'bash -s' <<'REMOTE'
set -euo pipefail
[ -d ~/mycelium/.git ] || git clone --quiet --branch deploy ~/repos/mycelium.git ~/mycelium
cd ~/mycelium
git fetch --quiet origin deploy && git checkout --quiet -B deploy origin/deploy
export PATH="$HOME/.local/opt/node22/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
npm ci --omit=dev --no-audit --no-fund --silent
gh auth setup-git

# Build tools for verifying fixes, installed for this user only.
command -v pnpm >/dev/null || npm install --silent --prefix ~/.local -g pnpm
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
