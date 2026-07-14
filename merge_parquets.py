#!/usr/bin/env python3
"""
Fuegt eine Liste von Parquet-Dateien zu einer einzigen Ausgabedatei
zusammen -- streaming, ohne alles in den RAM zu laden.

Die Liste der Eingabedateien wird zeilenweise ueber stdin uebergeben
(ein Pfad pro Zeile), NICHT per Ordner-Glob. Grund: wuerde man einfach
alle *.parquet in einem Ordner einlesen, koennte bei einem erneuten Lauf
im selben Zielordner versehentlich eine bereits vorhandene alte
Ausgabedatei mit eingelesen werden.

Voraussetzung: alle Eingabedateien haben identisches Schema. Wenn
pcap_to_parquet.py lief, ist das durch das feste SCHEMA_OVERRIDES-Dict
gewaehrleistet.

Usage:
    printf '%s\n' part1.parquet part2.parquet ... | merge_parquets.py <output.parquet>
"""
import sys
import polars as pl

def main():
    if len(sys.argv) != 2:
        print("Usage: printf '%s\\n' <parts...> | merge_parquets.py <output.parquet>", file=sys.stderr)
        sys.exit(1)

    out_path = sys.argv[1]
    paths = [line.strip() for line in sys.stdin if line.strip()]

    if not paths:
        print("[error] keine Eingabedateien via stdin erhalten", file=sys.stderr)
        sys.exit(1)

    lf = pl.scan_parquet(paths)
    lf.sink_parquet(out_path, compression="zstd")


if __name__ == "__main__":
    main()