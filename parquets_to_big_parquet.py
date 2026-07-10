#!/usr/bin/env python3
"""
Konvertiert eine einzelne pcap/pcapng-Datei (optional .zst-komprimiert)
via tshark -T fields nach Parquet.
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

# -- Schema ----------------------------------------------------------------
# WICHTIG: "-E occurrence=a" ist eine globale tshark-Option. Sie betrifft
# NICHT nur die Felder, die wir inhaltlich als "multi-value" ansehen
# (uri_path, uri_query) -- JEDES Feld kann bei mehreren Vorkommen im selben
# Frame kommasepariert werden (z.B. mehrere coap.opt.block_number-Werte,
# mehrere dtls.record.content_type in einem TCP-Segment etc.).
# Damit polars ueber viele Dateien hinweg IMMER dasselbe Schema inferiert
# (Voraussetzung fuer verlustfreies Mergen/Concatenieren), deklarieren wir
# alle potentiell wiederholbaren Felder explizit als Utf8 und lassen nur
# echte garantiert-einwertige Felder numerisch.
SCHEMA_OVERRIDES = {
    # Echte Frame-Level-Felder: garantiert genau ein Wert pro Frame.
    "frame.number": pl.Int64,
    "frame.time_epoch": pl.Float64,
    "frame.time_delta": pl.Float64,
    "frame.len": pl.Int64,
    "frame.protocols": pl.Utf8,
    # Ab hier bewusst ALLES Utf8: sobald ein Paket getunnelt/encapsuliert
    # ist (IP-in-IP, GRE, VXLAN, ...) oder mehrere Protokoll-Instanzen im
    # selben Frame auftauchen, joint tshark die Werte mit ',' -- z.B.
    # "ip.proto" = "1,17" bei ICMP-in-UDP-Tunnel o.ae. Das betrifft
    # potentiell JEDES Nicht-Frame-Feld, nicht nur die "offensichtlichen"
    # Multi-Value-Felder. Numerisch machen wir das erst nach dem Einlesen,
    # gezielt, nachdem klar ist welche Zeilen wirklich mehrwertig sind.
    "ip.src": pl.Utf8,
    "ip.dst": pl.Utf8,
    "ip.proto": pl.Utf8,
    "ip.ttl": pl.Utf8,
    "ipv6.src": pl.Utf8,
    "ipv6.dst": pl.Utf8,
    "ipv6.hlim": pl.Utf8,
    "udp.srcport": pl.Utf8,
    "udp.dstport": pl.Utf8,
    "udp.length": pl.Utf8,
    "tcp.srcport": pl.Utf8,
    "tcp.dstport": pl.Utf8,
    "tcp.len": pl.Utf8,
    "dtls.record.content_type": pl.Utf8,
    "dtls.record.version": pl.Utf8,
    "dtls.handshake.type": pl.Utf8,
    "coap.version": pl.Utf8,
    "coap.type": pl.Utf8,
    "coap.code": pl.Utf8,
    "coap.mid": pl.Utf8,
    "coap.token": pl.Utf8,
    "coap.token_len": pl.Utf8,
    "coap.opt.uri_path": pl.Utf8,
    "coap.opt.uri_query": pl.Utf8,
    "coap.opt.block_number": pl.Utf8,
    "coap.opt.block_mflag": pl.Utf8,
    "coap.opt.block_size": pl.Utf8,
    "coap.opt.observe": pl.Utf8,
    "coap.response_to": pl.Utf8,
    "coap.response_in": pl.Utf8,
    "coap.payload_length": pl.Utf8,
    "source_file": pl.Utf8,
}

# Felder, bei denen CoAP mehrere Instanzen pro Paket haben kann
# (z.B. mehrere Uri-Path-Optionen fuer /large/create).
# tshark joint diese standardmaessig mit ',' -> beim Analysieren splitten.
MULTI_VALUE_FIELDS = {"coap.opt.uri_path", "coap.opt.uri_query"}

ZST_SUFFIXES = (".zst",)


def is_zst(path: str) -> bool:
    return path.endswith(ZST_SUFFIXES)


def run_tshark(pcap_path: str) -> bytes:
    cmd = [
        "tshark", "-r", "-" if is_zst(pcap_path) else pcap_path, "-n",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=a",   # alle Vorkommen, comma-separiert
    ]
    for f in FIELDS:
        cmd += ["-e", f]

    if is_zst(pcap_path):
        # zstd -dc dekomprimiert nach stdout, tshark liest via "-r -" von stdin.
        # Kein temporäres Entpacken auf Platte nötig.
        zstd_proc = subprocess.Popen(
            ["zstd", "-dc", pcap_path],
            stdout=subprocess.PIPE,
        )
        try:
            proc = subprocess.run(
                cmd, stdin=zstd_proc.stdout, capture_output=True, check=True
            )
        finally:
            zstd_proc.stdout.close()
            ret = zstd_proc.wait()
            if ret != 0:
                raise subprocess.CalledProcessError(ret, ["zstd", "-dc", pcap_path])
        return proc.stdout
    else:
        proc = subprocess.run(cmd, capture_output=True, check=True)
        return proc.stdout


def main():
    if len(sys.argv) != 3:
        print("Usage: pcap_to_parquet.py <input.pcap[.zst]> <output.parquet>", file=sys.stderr)
        sys.exit(1)

    pcap_path, out_path = sys.argv[1], sys.argv[2]
    raw = run_tshark(pcap_path)

    if not raw.strip():
        print(f"[warn] keine Pakete/leer: {pcap_path}", file=sys.stderr)
        return

    lf = pl.scan_csv(
        io.BytesIO(raw),
        separator="|",
        infer_schema=False,
        schema_overrides=SCHEMA_OVERRIDES,
        null_values=[""],
        ignore_errors=True,
    )
    lf = lf.with_columns(pl.lit(pcap_path).alias("source_file"))
    lf.collect().write_parquet(out_path, compression="zstd")


if __name__ == "__main__":
    main()