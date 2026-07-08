#!/usr/bin/env python3
"""
Konvertiert eine einzelne pcap/pcapng-Datei via tshark -T fields nach Parquet.
Feldset deckt (a) generelle Analyse und (b) CoAP-spezifische Auswertung ab
(BAF/PAF, Request/Response-Matching, Fragmentierung via Block-Options).
"""
import sys
import io
import subprocess
import polars as pl

# -- Feldliste -----------------------------------------------------------
GENERAL_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.time_delta", "frame.len",
    "frame.protocols",
    "ip.src", "ip.dst", "ip.proto", "ip.ttl",
    "ipv6.src", "ipv6.dst", "ipv6.hlim",
    "udp.srcport", "udp.dstport", "udp.length",
    "tcp.srcport", "tcp.dstport", "tcp.len",
    "dtls.record.content_type", "dtls.record.version", "dtls.handshake.type",
]

COAP_FIELDS = [
    "coap.version", "coap.type", "coap.code", "coap.mid",
    "coap.token", "coap.token_len",
    "coap.opt.uri_path", "coap.opt.uri_query",
    "coap.opt.block_number", "coap.opt.block_mflag", "coap.opt.block_size",
    "coap.opt.observe",
    "coap.response_to", "coap.response_in",
    "coap.payload_length",
]

FIELDS = GENERAL_FIELDS + COAP_FIELDS

# Felder, bei denen CoAP mehrere Instanzen pro Paket haben kann
# (z.B. mehrere Uri-Path-Optionen fuer /large/create).
# tshark joint diese standardmaessig mit ',' -> beim Analysieren splitten.
MULTI_VALUE_FIELDS = {"coap.opt.uri_path", "coap.opt.uri_query"}


def run_tshark(pcap_path: str) -> bytes:
    cmd = [
        "tshark", "-r", pcap_path, "-n",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=a",   # alle Vorkommen, comma-separiert
    ]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, check=True)
    return proc.stdout


def main():
    if len(sys.argv) != 3:
        print("Usage: pcap_to_parquet.py <input.pcap> <output.parquet>", file=sys.stderr)
        sys.exit(1)

    pcap_path, out_path = sys.argv[1], sys.argv[2]
    raw = run_tshark(pcap_path)
    if not raw.strip():
        print(f"[warn] keine Pakete/leer: {pcap_path}", file=sys.stderr)
        return

    lf = pl.scan_csv(
        io.BytesIO(raw),
        separator="|",
        infer_schema_length=20000,
        truncate_ragged_lines=True,
        null_values=[""],
    )

    lf = lf.with_columns(pl.lit(pcap_path).alias("source_file"))
    lf.collect().write_parquet(out_path, compression="zstd")


if __name__ == "__main__":
    main()
    