#!/usr/bin/env bash
# The whole verification, against one fresh release build. Needs podman, /dev/kvm,
# the images in ./images (tools/fetch-images.sh) and the two containers:
#   podman build -t cii-dev     -f tools/Containerfile         tools
#   podman build -t cii-guestfs -f tools/Containerfile.guestfs tools
set -u
cd "$(dirname "$0")/.."
LOG=fixtures/out/final
mkdir -p "$LOG" fixtures/out/scratch
DEV=(podman run --rm -v "$PWD":/work -v cii-cargo:/usr/local/cargo/registry -w /work -e CARGO_TERM_COLOR=never localhost/cii-dev:latest)
GFS=(podman run --rm --device /dev/kvm -v "$PWD":/work -v "$PWD/images":/images:ro -v "$PWD/fixtures/out/scratch":/scratch localhost/cii-guestfs:latest)
IMAGES=$(cd images && ls *.qcow2 | sed 's|^|/images/|')
status=0
step() {
    local name=$1; shift
    if "$@" > "$LOG/$name.log" 2>&1; then echo "PASS $name"; else echo "FAIL $name (see $LOG/$name.log)"; status=1; fi
}

rm -rf fixtures/out/scratch/native
step build        "${DEV[@]}" bash -c 'cargo build --release && sha256sum target/release/cloud-image-inspector && cargo tree'
step lint         "${DEV[@]}" bash -c 'cargo fmt --check && cargo clippy --all-targets --release -- -D warnings'
step vectors      "${DEV[@]}" bash -c 'python3 tools/make-vectors.py fixtures/out/vectors && CII_REQUIRE=1 cargo test --release --lib --test compress --test pkgdb -- --nocapture'
step fixtures     "${DEV[@]}" bash -c 'python3 tools/make_fixtures.py fixtures/out/fs && python3 tools/verify_fixtures.py fixtures/out/fs'
# Fuzzing corrupts the fixture images, so it runs after they exist.
step fuzz         "${DEV[@]}" bash -c 'CII_REQUIRE=1 CII_FUZZ_ITERS=1500 cargo test --release --test fuzz_images -- --nocapture 2>&1 | grep -v "^iteration"; exit ${PIPESTATUS[0]}'
step kernel       "${GFS[@]}" python3 /work/tools/kernel_fixtures.py
step real         "${GFS[@]}" python3 /work/tools/verify_real.py $IMAGES
step config-facts "${GFS[@]}" python3 /work/tools/verify_config_facts.py $IMAGES
native() {
    local base=fixtures/out/scratch/native d
    for d in "$base"/*/; do
        case "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manager"])' "$d/tool.json")" in
            apk)    podman run --rm -v "$PWD/$d":/r docker.io/library/alpine:3.24 sh -c 'apk --root /r --no-network info -v 2>/dev/null' > "$d/native.txt" ;;
            pacman) podman run --rm -v "$PWD/$d":/r:ro docker.io/library/archlinux:latest sh -c 'pacman -Q --dbpath /r/var/lib/pacman 2>/dev/null' > "$d/native.txt" ;;
        esac
    done
    "${DEV[@]}" python3 tools/verify_native.py "$base"
}
step native       native
step facts-table  "${DEV[@]}" bash -c './target/release/cloud-image-inspector --json images/*.qcow2 | python3 tools/facts_table.py'
exit $status
