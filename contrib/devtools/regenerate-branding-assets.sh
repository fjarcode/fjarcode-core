#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source_logo="$repo_root/codefalcon.png"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

if ! command -v convert >/dev/null 2>&1; then
    echo "error: ImageMagick 'convert' is required" >&2
    exit 1
fi

if [[ ! -f "$source_logo" ]]; then
    echo "error: canonical logo not found at $source_logo" >&2
    exit 1
fi

render_square() {
    local size="$1"
    local out="$2"
    convert "$source_logo" -background none -gravity center -resize "${size}x${size}" -extent "${size}x${size}" "$out"
}

for size in 16 32 64 128 256 512; do
    render_square "$size" "$repo_root/src/qt/res/icons/codefalcon_${size}.png"
done

cp "$source_logo" "$repo_root/src/qt/res/icons/codefalcon_original.png"
cp "$source_logo" "$repo_root/doc/codefalcon_logo_doxygen.png"
cp "$source_logo" "$repo_root/src/qt/res/icons/codefalcon.png"

for size in 16 32 64 128 256; do
    render_square "$size" "$repo_root/share/pixmaps/codefalcon${size}.png"
    convert "$repo_root/share/pixmaps/codefalcon${size}.png" "$repo_root/share/pixmaps/codefalcon${size}.xpm"
    cp "$repo_root/share/pixmaps/codefalcon${size}.png" "$tmp_dir/codefalcon-${size}.png"
done

convert \
    "$tmp_dir/codefalcon-16.png" \
    "$tmp_dir/codefalcon-32.png" \
    "$tmp_dir/codefalcon-64.png" \
    "$tmp_dir/codefalcon-128.png" \
    "$tmp_dir/codefalcon-256.png" \
    "$repo_root/src/qt/res/icons/codefalcon.ico"

cp "$repo_root/src/qt/res/icons/codefalcon.ico" "$repo_root/src/qt/res/icons/codefalcon_testnet.ico"
cp "$repo_root/src/qt/res/icons/codefalcon.ico" "$repo_root/share/pixmaps/codefalcon.ico"

convert \
    "$repo_root/src/qt/res/icons/codefalcon_16.png" \
    "$repo_root/src/qt/res/icons/codefalcon_32.png" \
    "$repo_root/src/qt/res/icons/codefalcon_64.png" \
    "$repo_root/src/qt/res/icons/codefalcon_128.png" \
    "$repo_root/src/qt/res/icons/codefalcon_256.png" \
    "$repo_root/src/qt/res/icons/codefalcon_512.png" \
    "$repo_root/src/qt/res/icons/codefalcon.icns"

render_square 36 "$repo_root/src/qt/android/res/drawable-ldpi/codefalcon.png"
render_square 48 "$repo_root/src/qt/android/res/drawable-mdpi/codefalcon.png"
render_square 72 "$repo_root/src/qt/android/res/drawable-hdpi/codefalcon.png"
render_square 96 "$repo_root/src/qt/android/res/drawable-xhdpi/codefalcon.png"
render_square 144 "$repo_root/src/qt/android/res/drawable-xxhdpi/codefalcon.png"
render_square 192 "$repo_root/src/qt/android/res/drawable-xxxhdpi/codefalcon.png"

convert -size 150x57 xc:'#f4efe6' \
    \( "$source_logo" -background none -gravity center -resize 42x42 -extent 42x42 \) \
    -gravity west -geometry +12+0 -composite \
    "BMP3:$repo_root/share/pixmaps/nsis-header.bmp"

convert -size 164x314 xc:'#f4efe6' \
    \( "$source_logo" -background none -gravity center -resize 116x116 -extent 116x116 \) \
    -gravity north -geometry +0+28 -composite \
    "BMP3:$repo_root/share/pixmaps/nsis-wizard.bmp"

echo "Regenerated branding assets from $source_logo"