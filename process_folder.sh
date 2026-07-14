#!/usr/bin/env bash
# Konvertiert eine Reihe von pcap(.zst)-Dateien parallel zu Parquet und
# fuegt die Ergebnisse zu einer einzigen Ausgabedatei zusammen.
#
# Dateien werden NICHT per find gesucht:
#   - MIT --range START:END: Basis-String + durchnummerierter Bereich
#     Dateiname = "${BASE_STRING}${nummer}${EXT}"
#   - OHNE --range: BASE_STRING ist direkt der Pfad zu genau einer Datei
#
# Kein temporaeres Verzeichnis (kein mktemp/tmp): alle Zwischen-Parquets
# (und CSVs, falls --keep-csv) landen direkt im selben Ordner wie die
# finale Ausgabedatei OUTPUT. Nach erfolgreichem Merge werden nur die
# Zwischen-Parquets wieder geloescht; CSVs bleiben bei --keep-csv liegen.
#
# Usage:
#   ./process_folder.sh <base_string> <output.parquet> [--range START:END] \
#       [--jobs N] [--ext .pcap.zst] [--pad WIDTH] [--keep-csv]
#
# Beispiele:
#   ./process_folder.sh data/raw/ddos_1/packet_ data/interim/ddos_1/out.parquet --range 400:1000
#   -> erwartet Dateien data/raw/ddos_1/packet_400.pcap.zst ... packet_1000.pcap.zst
#
#   ./process_folder.sh data/raw/ddos_1/packet_400.pcap.zst data/interim/ddos_1/out.parquet
#   -> konvertiert nur diese eine Datei
set -euo pipefail

SCRIPT_START_TS=$(date +%s)

usage() {
    echo "Usage: $0 <base_string> <output.parquet> [--range START:END] [--jobs N] [--ext .pcap.zst] [--pad WIDTH] [--keep-csv]" >&2
    exit 1
}

[[ $# -lt 2 ]] && usage

BASE_STRING="$1"; shift
OUTPUT="$1"; shift

# Default: ein Viertel der verfuegbaren Kerne. Volle Kernzahl (nproc) kann
# je nach I/O-Last/Speicherbandbreite zu Overcommitting fuehren, wenn jeder
# tshark-Prozess selbst schon nennenswert CPU-lastig ist -- 1/4 ist ein
# konservativerer Default, ueberschreibbar mit --jobs.
JOBS=$(( $(nproc) / 4 ))
if (( JOBS < 1 )); then
    JOBS=1
fi
KEEP_CSV="false"
RANGE_START=""
RANGE_END=""
EXT=".pcap.zst"
PAD=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --range)
            [[ $# -lt 2 ]] && { echo "[error] --range braucht START:END" >&2; usage; }
            RANGE_START="${2%%:*}"
            RANGE_END="${2##*:}"
            shift 2
            ;;
        --jobs)
            [[ $# -lt 2 ]] && { echo "[error] --jobs braucht einen Wert" >&2; usage; }
            JOBS="$2"
            shift 2
            ;;
        --ext)
            [[ $# -lt 2 ]] && { echo "[error] --ext braucht einen Wert" >&2; usage; }
            EXT="$2"
            shift 2
            ;;
        --pad)
            [[ $# -lt 2 ]] && { echo "[error] --pad braucht einen Wert" >&2; usage; }
            PAD="$2"
            shift 2
            ;;
        --keep-csv)
            KEEP_CSV="true"
            shift
            ;;
        *)
            echo "[error] Unbekanntes Argument: $1" >&2
            usage
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUTPUT_DIR="$(dirname "$OUTPUT")"
mkdir -p "$OUTPUT_DIR"

FILES=()
PARTS=()
MISSING=0

if [[ -n "$RANGE_START" ]]; then
    echo "[*] Baue Dateiliste: ${BASE_STRING}{${RANGE_START}..${RANGE_END}}${EXT}"
    for (( num=RANGE_START; num<=RANGE_END; num++ )); do
        if [[ "$PAD" -gt 0 ]]; then
            num_str="$(printf "%0${PAD}d" "$num")"
        else
            num_str="$num"
        fi
        f="${BASE_STRING}${num_str}${EXT}"
        if [[ -f "$f" ]]; then
            base="$(basename "$f")"
            base="${base%.zst}"
            base="${base%.pcap*}"
            FILES+=("$f")
            PARTS+=("$OUTPUT_DIR/${base}.parquet")
        else
            MISSING=$((MISSING + 1))
        fi
    done
else
    # Kein --range angegeben: BASE_STRING ist dann direkt der Pfad zu
    # genau EINER zu konvertierenden Datei.
    echo "[*] Kein --range angegeben, verarbeite einzelne Datei: $BASE_STRING"
    if [[ -f "$BASE_STRING" ]]; then
        base="$(basename "$BASE_STRING")"
        base="${base%.zst}"
        base="${base%.pcap*}"
        FILES+=("$BASE_STRING")
        PARTS+=("$OUTPUT_DIR/${base}.parquet")
    else
        MISSING=1
    fi
fi

echo "[*] ${#FILES[@]} Dateien gefunden, $MISSING erwartete Datei(en) fehlen."

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "[error] Keine zu verarbeitenden Dateien gefunden." >&2
    exit 1
fi

echo "[*] Konvertiere mit $JOBS parallelen Jobs -> $OUTPUT_DIR"

TOTAL_FILES=${#FILES[@]}
COUNTER_FILE="$(mktemp -u "${OUTPUT_DIR}/.counter.XXXXXX")"
COUNTER_LOCK="${COUNTER_FILE}.lock"
echo 0 > "$COUNTER_FILE"

printf '%s\0' "${FILES[@]}" | xargs -0 -P "$JOBS" -I{} bash -c '
    f="$1"
    base="$(basename "$f")"
    base="${base%.zst}"
    base="${base%.pcap*}"
    out="'"$OUTPUT_DIR"'/${base}.parquet"

    csv_flag=()
    if [[ "'"$KEEP_CSV"'" == "true" ]]; then
        csv_flag=(--keep-csv)
    fi

    if ! uv run --project "'"$SCRIPT_DIR"'" "'"$SCRIPT_DIR"'/pcap_to_parquet.py" "$f" "$out" "${csv_flag[@]}"; then
        echo "[error] Konvertierung fehlgeschlagen: $f" >&2
    fi

    # Zaehler atomar hochzaehlen (flock verhindert Race Conditions bei
    # gleichzeitigem Schreibzugriff mehrerer paralleler Jobs).
    (
        flock -x 200
        n=$(<"'"$COUNTER_FILE"'")
        n=$((n + 1))
        echo "$n" > "'"$COUNTER_FILE"'"
        echo "[progress] $n / '"$TOTAL_FILES"' fertig ($base)"
    ) 200>"'"$COUNTER_LOCK"'"
' _ {}

rm -f "$COUNTER_FILE" "$COUNTER_LOCK"

EXISTING_PARTS=()
for p in "${PARTS[@]}"; do
    [[ -f "$p" ]] && EXISTING_PARTS+=("$p")
done

N_OK=${#EXISTING_PARTS[@]}
echo "[*] $N_OK / ${#FILES[@]} Dateien erfolgreich konvertiert."

if [[ "$N_OK" -eq 0 ]]; then
    echo "[error] Keine Parquet-Dateien erzeugt, breche ab." >&2
    exit 1
fi

echo "[*] Merge -> $OUTPUT"
printf '%s\n' "${EXISTING_PARTS[@]}" | uv run --project "$SCRIPT_DIR" "$SCRIPT_DIR/merge_parquets.py" "$OUTPUT"

echo "[*] Raeume Zwischen-Parquets auf ..."
for p in "${EXISTING_PARTS[@]}"; do
    rm -f "$p"
done

echo "[*] Fertig: $OUTPUT"

SCRIPT_END_TS=$(date +%s)
ELAPSED=$((SCRIPT_END_TS - SCRIPT_START_TS))
printf '[*] Gesamtlaufzeit: %02d:%02d:%02d (%ds)\n' \
    $((ELAPSED / 3600)) $((ELAPSED % 3600 / 60)) $((ELAPSED % 60)) "$ELAPSED"