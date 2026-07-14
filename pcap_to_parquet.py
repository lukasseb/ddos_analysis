#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path

import polars as pl

fields = [
    # general
    "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ip.dst", "ip.proto", "ip.ttl",
    "ipv6.src", "ipv6.dst", "ipv6.hlim",
    "udp.srcport", "udp.dstport", "udp.length",
    "tcp.srcport", "tcp.dstport", "tcp.len",
    # coap
    "coap.version", "coap.type", "coap.code", "coap.mid",
    "coap.token", "coap.token_len",
    "coap.opt.uri_path", "coap.opt.uri_query",
    "coap.opt.block_number", "coap.opt.block_mflag", "coap.opt.block_size",
    "coap.opt.observe",
    "coap.response_to", "coap.response_in",
    "coap.payload_length",
]

schema = {
    # generell
    "frame.time_epoch": pl.Float64,
    "frame.len": pl.UInt32,
    "frame.protocols": pl.String,
    "ip.src": pl.String,
    "ip.dst": pl.String,
    "ip.proto": pl.Int64,
    "ip.ttl": pl.UInt8,
    "ipv6.src": pl.String,
    "ipv6.dst": pl.String,
    "ipv6.hlim": pl.UInt8,
    "udp.srcport": pl.UInt16,
    "udp.dstport": pl.UInt16,
    "udp.length": pl.UInt16,
    "tcp.srcport": pl.UInt16,
    "tcp.dstport": pl.UInt16,
    "tcp.len": pl.UInt32,
    # coap
    "coap.version": pl.UInt8,
    "coap.type": pl.UInt8,
    "coap.code": pl.UInt8,
    "coap.mid": pl.UInt16,
    "coap.token": pl.String,
    "coap.token_len": pl.UInt8,
    "coap.opt.uri_path": pl.String,
    "coap.opt.uri_query": pl.String,
    "coap.opt.block_number": pl.String,
    "coap.opt.block_mflag": pl.String,
    "coap.opt.block_size": pl.String,
    "coap.opt.observe": pl.String,
    "coap.response_to": pl.String,
    "coap.response_in": pl.String,
    "coap.payload_length": pl.UInt32,
    "source_file": pl.String,
}

multi_value_fields = {"ip.proto", "ip.ttl", "coap.opt.uri_path", "coap.opt.uri_query"}

def run_tshark(pcap_path: str) -> bytes:
    cmd = [
        "tshark", "-r", pcap_path, "-n",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=|",
        "-E", "aggregator=,",
        "-E", "quote=n",
        "-E", "occurrence=a",
    ]
    for f in fields:
        cmd += ["-e", f]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    if result.stderr:
        print(result.stderr.decode(errors="replace"), file=sys.stderr)

    return result.stdout

def main():
    if len(sys.argv) not in (3, 4):
        print(
            "Usage: pcap_to_parquet.py <input.pcap[.zst]> <output.parquet> [--keep-csv]",
            file=sys.stderr,
        )
        sys.exit(1)

    pcap_path, out_path = sys.argv[1], sys.argv[2]
    keep_csv = "--keep-csv" in sys.argv[3:]

    raw = run_tshark(pcap_path)

    if not raw.strip():
        print(f"[warn] keine Pakete/leer: {pcap_path}", file=sys.stderr)
        return

    csv_path = Path(out_path).with_suffix(".csv")
    csv_path.write_bytes(raw)

    lf = pl.scan_csv(
        csv_path,
        separator="|",
        infer_schema=False,
        schema_overrides=schema,
        truncate_ragged_lines=True,
        # ignore_errors=True,
        null_values=[""],
    )
    lf = lf.with_columns(pl.lit(pcap_path).alias("source_file"))

    # frame.time_epoch (float, Sekunden seit Epoch) -> echtes Datetime
    lf = lf.with_columns(
        (pl.col("frame.time_epoch") * 1_000_000)
        .cast(pl.Int64)
        .cast(pl.Datetime(time_unit="us"))
        .alias("frame.time")
    )

    lf.collect().write_parquet(out_path, compression="zstd")

    if not keep_csv:
        csv_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()