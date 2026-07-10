#!/usr/bin/env bash
# Konvertiert alle *.pcap.zst / *.pcapng.zst in INPUT_DIR parallel zu
# Parquet und fuegt die Ergebnisse zu einer einzigen Ausgabedatei zusammen.
#
# Usage:
#   ./process_folder.sh <input_dir> <output.parquet> [parallel_jobs] [--keep-tmp]
set -euo pipefail

INPUT_DIR="${1:?Usage: $0 <input_dir> <output.parquet> [parallel_jobs] [--keep-tmp]}"
OUTPUT="${2:?Usage: $0 <input_dir> <output.parquet> [parallel_jobs] [--keep-tmp]}"
JOBS="${3:-$(nproc)}"
KEEP_TMP="${4:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"

cleanup() {
    if [[ "$KEEP_TMP" != "--keep-tmp" ]]; then
        rm -rf "$TMP_DIR"
    else
        echo "[*] Temp-Verzeichnis behalten: $TMP_DIR"
    fi
}
trap cleanup EXIT

echo "[*] Suche pcap(.zst)-Dateien in $INPUT_DIR ..."
mapfile -d '' FILES < <(find "$INPUT_DIR" -type f \( \
    -name '*.pcap' -o -name '*.pcapng' -o \
    -name '*.pcap.zst' -o -name '*.pcapng.zst' \) -print0)

echo "[*] ${#FILES[@]} Dateien gefunden. Konvertiere mit $JOBS parallelen Jobs -> $TMP_DIR"

printf '%s\0' "${FILES[@]}" | xargs -0 -P "$JOBS" -I{} bash -c '
    f="$1"
    base="$(basename "$f")"
    base="${base%.zst}"
    out="'"$TMP_DIR"'/${base%.pcap*}_$$.parquet"
    if ! python3 "'"$SCRIPT_DIR"'/pcap_to_parquet.py" "$f" "$out"; then
        echo "[error] Konvertierung fehlgeschlagen: $f" >&2
    fi
' _ {}

N_OK=$(find "$TMP_DIR" -name '*.parquet' | wc -l)
echo "[*] $N_OK / ${#FILES[@]} Dateien erfolgreich konvertiert."

if [[ "$N_OK" -eq 0 ]]; then
    echo "[error] Keine Parquet-Dateien erzeugt, breche ab." >&2
    exit 1
fi

echo "[*] Merge -> $OUTPUT"
python3 "$SCRIPT_DIR/merge_parquets.py" "$TMP_DIR" "$OUTPUT"

echo "[*] Fertig: $OUTPUT"
