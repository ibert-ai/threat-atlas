#!/usr/bin/env bash
# Downloads the newest Threat Atlas / AtlasSOC file for an update channel and verifies its SHA-256.
# macOS and Linux terminal. Needs bash, curl, python3 and shasum or sha256sum.
# It never installs anything: it prints the path of the verified file. See docs/UPDATE-CHANNELS.md.
#
#   scripts/get-latest.sh --channel rc --allow-unsigned-feed
#   scripts/get-latest.sh --product screensaver --channel stable --platform macos-universal --allow-unsigned-feed
#
# Channels: stable (default), rc, beta. Fallback: beta -> rc -> stable; rc -> stable.
set -euo pipefail

DEFAULT_FEED="https://raw.githubusercontent.com/Ibert-Iam/threat-atlas/update-feed/feed.json"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
product="atlassoc"; channel="stable"; platform=""; kind="auto"
feed_url="$DEFAULT_FEED"; feed_file=""; out_dir="${XDG_CACHE_HOME:-$HOME/.cache}/threat-atlas/downloads"
resolve_only=0; allow_unsigned=0

usage() {
  cat <<'EOF'
Usage: get-latest.sh [--product atlassoc|screensaver] [--channel stable|rc|beta]
                     [--platform macos-universal|linux-x64|windows-x64] [--kind auto|installer|portable]
                     [--feed-url URL | --feed-file FILE] [--out-dir DIR]
                     [--resolve-only] [--allow-unsigned-feed]

  --resolve-only         print version, channel, url, sha256, size, name and stop (no download)
  --allow-unsigned-feed  required until feed signatures exist; the file is then protected by
                         its SHA-256 from the feed only. Verify the OS signature yourself.
EOF
}
die() { echo "get-latest: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --product) product="${2:?}"; shift 2 ;;
    --channel) channel="${2:?}"; shift 2 ;;
    --platform) platform="${2:?}"; shift 2 ;;
    --kind) kind="${2:?}"; shift 2 ;;
    --feed-url) feed_url="${2:?}"; shift 2 ;;
    --feed-file) feed_file="${2:?}"; shift 2 ;;
    --out-dir) out_dir="${2:?}"; shift 2 ;;
    --resolve-only) resolve_only=1; shift ;;
    --allow-unsigned-feed) allow_unsigned=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

if [ -z "$platform" ]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-*) platform="macos-universal" ;;
    Linux-x86_64) platform="linux-x64" ;;
    *) die "cannot detect the platform; pass --platform" ;;
  esac
fi
command -v python3 >/dev/null || die "python3 is required (macOS: xcode-select --install)"
[ -f "$here/update_feed.py" ] || die "update_feed.py must sit next to this script"
if [ "$allow_unsigned" -ne 1 ]; then
  die "feed signature checking is not implemented yet. Re-run with --allow-unsigned-feed to continue with SHA-256 only"
fi

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
if [ -n "$feed_file" ]; then
  cp "$feed_file" "$work/feed.json"
else
  case "$feed_url" in https://*) ;; *) die "the feed URL must be https" ;; esac
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 30 --max-filesize 1000000 -o "$work/feed.json" "$feed_url" \
    || die "could not download the feed from $feed_url"
fi

line="$(python3 "$here/update_feed.py" pick-asset "$work/feed.json" --product "$product" --channel "$channel" \
        --platform "$platform" --kind "$kind")" || die "no release available for $product / $channel / $platform"
IFS=$'\t' read -r version found_channel url sha size name <<<"$line"
case "$url" in https://github.com/Ibert-Iam/threat-atlas/releases/download/*) ;; *) die "refusing a download URL outside the project's GitHub releases" ;; esac
# update_feed.py already validated the URL by its parsed parts; refuse anything a client could normalise elsewhere.
case "$url" in *..*|*%*|*\\*|*\?*|*\#*|*@*) die "refusing a download URL with traversal or special characters" ;; esac
case "$name" in *[!A-Za-z0-9._-]*|"") die "refusing an unsafe file name" ;; esac

echo "Channel $channel -> $product $version ($found_channel), $name, $size bytes" >&2
if [ "$resolve_only" -eq 1 ]; then printf '%s\n' "$line"; exit 0; fi

# Per-user directory (0700), never a shared /tmp path; refuse a link or a directory owned by someone else.
umask 077
mkdir -p "$out_dir"
[ -d "$out_dir" ] && [ ! -L "$out_dir" ] && [ -O "$out_dir" ] || die "refusing the download folder $out_dir (not a plain directory owned by you)"
chmod 700 "$out_dir"
part="$(mktemp "$out_dir/$name.XXXXXX")"; dest="$out_dir/$name"
trap 'rm -rf "$work"; rm -f "$part"' EXIT
curl -fL --proto '=https' --tlsv1.2 --max-time 600 --max-filesize "$size" -o "$part" "$url" || die "download failed"
[ "$(wc -c <"$part" | tr -d ' ')" = "$size" ] || { rm -f "$part"; die "size differs from the feed; file removed"; }
if command -v sha256sum >/dev/null; then got="$(sha256sum "$part" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$part" | cut -d' ' -f1)"; fi
[ "$got" = "$sha" ] || { rm -f "$part"; die "SHA-256 mismatch; file removed"; }
[ ! -L "$dest" ] || { rm -f "$part"; die "refusing to replace a link at $dest"; }
mv -f "$part" "$dest"
echo "SHA-256 verified: $sha" >&2
echo "Nothing was installed. Unsigned feed: also check the operating-system signature before you open it." >&2
printf '%s\n' "$dest"
