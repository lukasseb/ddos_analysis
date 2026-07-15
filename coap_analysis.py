#!/usr/bin/env python3
"""
DDoS / CoAP Amplification Auswertung.

Konvertiert aus coap_analysis.ipynb. Analysiert einen Wireshark/tshark-Export
(als Parquet, siehe pcap_to_parquet.py) auf CoAP-spezifische Metriken und
klassifiziert Requests heuristisch in die 3 bekannten CoAP-Amplification-
Angriffsarten (RFC draft-irtf-t2trg-amplification-attacks):

    - simple           : klassische Amplification durch groessere Response
                          (z.B. .well-known/core Enumeration, Block-wise Transfer)
    - observer          : Observe-Option (RFC 7641) fuehrt zu mehreren
                          asynchronen Responses auf einen einzigen Request
    - group_request     : Request an eine Multicast-Adresse (RFC 7390),
                          potenziell mehrere Responses von mehreren Hosts
    - not_identifiable  : Request ohne erkennbares Amplification-Muster
                          bzw. ohne korrelierbare Response

Hinweis: Die Klassifikation ist heuristisch. Sie basiert auf einer
Token+Client-IP Korrelation (asof-Join ueber die Zeit), da frame.number
nicht im Feld-Set des tshark-Exports enthalten ist und multicast-Antworten
ohnehin nicht ueber die Ziel-IP des Requests korrelierbar sind (die Antwort
kommt unicast von der jeweiligen Server-IP, nicht von der Multicast-Adresse).
Fuer eine belastbare Auswertung in der Thesis sollte diese Logik anhand von
Ground-Truth-Traces validiert werden.
"""

import gc
from pathlib import Path
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import polars as pl
import time

# --------------------------------------------------------------------------
# Global parameters
# --------------------------------------------------------------------------

SERVER_IP = "141.22.28.227"
PARQUET_FILE = "data/interim/ddos_1/batch_1_1000.parquet"
PARQUET_FOLDER = "data/processed/ddos_1/batch_1_1000/"
PLOT_FOLDER = "plots/batch_1_1000/"

# CoAP Request-Codes (1 byte, Klasse 0.xx)
COAP_REQUEST_CODES = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}

# Multicast-Praefixe fuer Group-Requests (RFC 7390)
IPV4_MULTICAST_PREFIX = "224."
IPV6_MULTICAST_PREFIX = "ff0"

# Korrelationsfenster fuer die Request/Response-Zuordnung (Sekunden)
RESPONSE_CORRELATION_TOLERANCE_S = 30.0


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def ensure_plot_folder() -> Path:
    plot_dir = Path(PLOT_FOLDER)
    plot_dir.mkdir(parents=True, exist_ok=True)
    return plot_dir


def save_and_close(fig, name: str, plot_dir: Path) -> None:
    fig.savefig(plot_dir / f"{name}.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def format_coap_code(code: int) -> str:
    """Formatiert einen numerischen CoAP-Code als 'c.dd' bzw. Methodennamen."""
    if code in COAP_REQUEST_CODES:
        return COAP_REQUEST_CODES[code]
    code_class = code // 32
    detail = code % 32
    return f"{code_class}.{detail:02d}"


def top_n_plus_other(df: pl.DataFrame, label_col: str, value_col: str, top_n: int = 5):
    """Reduziert ein sortiertes count-DataFrame auf Top-N + 'Sonstige'."""
    total = df[value_col].sum()
    top = df.head(top_n)
    rest = df.tail(max(len(df) - top_n, 0))
    rest_sum = rest[value_col].sum() if len(rest) > 0 else 0

    labels = top[label_col].to_list()
    values = top[value_col].to_list()
    if rest_sum > 0:
        labels.append("Sonstige")
        values.append(rest_sum)
    return labels, values, total


def stacked_single_bar(labels, values, total, title: str, xlabel: str, plot_dir: Path, name: str):
    colors = cm.tab10.colors[: len(labels)]
    fig, ax = plt.subplots(figsize=(10, 3))

    left = 0
    for label, value, color in zip(labels, values, colors):
        pct = value / total * 100
        ax.barh(0, value, left=left, color=color, edgecolor="white", label=label)
        ax.text(
            left + value / 2, 0, f"{pct:.2f}%",
            ha="center", va="center", fontsize=9,
            color="white" if pct > 3 else "black",
        )
        left += value

    ax.set_xlim(0, total)
    ax.set_yticks([])
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.3), ncol=len(labels))
    fig.tight_layout()
    save_and_close(fig, name, plot_dir)


def grouped_bar(labels, values, title: str, xlabel: str, plot_dir: Path, name: str, log_scale=False):
    total = sum(values)
    colors = cm.tab20.colors[: len(labels)]
    fig, ax = plt.subplots(figsize=(10, max(3, 0.4 * len(labels))))

    y_pos = range(len(labels))
    ax.barh(y_pos, values, color=colors)
    for i, v in enumerate(values):
        pct = v / total * 100 if total else 0
        ax.text(v * 1.01, i, f"{v:,} ({pct:.2f}%)", va="center", fontsize=8)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    if log_scale:
        ax.set_xscale("log")
        xlabel = f"{xlabel} (log scale)"
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    fig.tight_layout()
    save_and_close(fig, name, plot_dir)


# --------------------------------------------------------------------------
# Data loading
# --------------------------------------------------------------------------

def load_data() -> pl.LazyFrame:
    lf = pl.scan_parquet(PARQUET_FILE).drop(
        "dtls.record.content_type", "dtls.record.version", "dtls.handshake.type"
    )
    return lf


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

def metric_general_coap_share(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Anteil CoAP-Pakete am Gesamttraffic."""
    lf_coap = lf.filter(pl.col("coap.version").is_not_null())

    total_packets = lf.select(pl.len()).collect().item()
    coap_packets = lf_coap.select(pl.len()).collect().item()

    print(f"All pakets           : {total_packets:>12,}")
    print(f"CoAP pakets          : {coap_packets:>12,}")
    print(f"CoAP distribution    : {coap_packets / total_packets:.2%}")

    return lf_coap


def metric_coap_message_types(lf_coap: pl.LazyFrame, plot_dir: Path) -> None:
    """Verteilung von CON / NON / ACK / RST."""
    type_names = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}

    df = (
        lf_coap.group_by("coap.type")
        .agg(pl.len().alias("count"))
        .collect()
        .sort("count", descending=True)
        .with_columns(
            pl.col("coap.type").cast(pl.Int64).replace_strict(type_names, default="unknown").alias("type_name")
        )
    )

    labels, values, total = top_n_plus_other(df, "type_name", "count", top_n=4)
    stacked_single_bar(
        labels, values, total,
        title="CoAP Message Type Distribution",
        xlabel="Packets",
        plot_dir=plot_dir, name="coap_message_types",
    )
    del df
    gc.collect()


def metric_coap_code_distribution(lf_coap: pl.LazyFrame, plot_dir: Path) -> None:
    """Haeufigste CoAP-Codes (Requests wie Responses gemischt)."""
    df = (
        lf_coap.group_by("coap.code")
        .agg(pl.len().alias("count"))
        .collect()
        .sort("count", descending=True)
        .with_columns(
            pl.col("coap.code").cast(pl.Int64).map_elements(format_coap_code, return_dtype=pl.String).alias("code_name")
        )
    )

    labels, values, _total = top_n_plus_other(df, "code_name", "count", top_n=8)
    grouped_bar(
        labels, values,
        title="CoAP Code Distribution (Top 8)",
        xlabel="Packets",
        plot_dir=plot_dir, name="coap_code_distribution",
    )
    del df
    gc.collect()


def metric_ip_protocol_distribution(lf: pl.LazyFrame, plot_dir: Path) -> None:
    """Verteilung ueber ip.proto, Top 5 + Sonstige, als gestapelter Bar."""
    df = (
        lf.group_by("ip.proto")
        .agg(pl.len().alias("count"))
        .collect()
        .sort("count", descending=True)
    )
    labels = [str(x) for x in df["ip.proto"].to_list()]
    values = df["count"].to_list()

    # top_n_plus_other erwartet Spaltennamen, daher hier manuell mit String-Labels
    total = sum(values)
    top_labels, top_values = labels[:5], values[:5]
    rest_sum = sum(values[5:])
    if rest_sum > 0:
        top_labels.append("Sonstige")
        top_values.append(rest_sum)

    stacked_single_bar(
        top_labels, top_values, total,
        title="IP Protocol Distribution",
        xlabel="Packets",
        plot_dir=plot_dir, name="ip_protocol_distribution",
    )
    del df
    gc.collect()


def metric_top_source_ips(lf: pl.LazyFrame, plot_dir: Path, top_n: int = 20) -> None:
    """Top N Source-IPs nach Bytes (potenzielle Reflektoren/Angreifer)."""
    df = (
        lf.group_by("ip.src")
        .agg([
            pl.len().alias("packets"),
            pl.col("frame.len").sum().alias("bytes"),
        ])
        .sort("bytes", descending=True)
        .head(top_n)
        .collect()
    )

    labels = df["ip.src"].to_list()
    values = df["bytes"].to_list()
    grouped_bar(
        labels, values,
        title=f"Top {top_n} Source IPs by Bytes",
        xlabel="Bytes",
        plot_dir=plot_dir, name="top_source_ips_bytes",
        log_scale=True,
    )
    del df
    gc.collect()


def metric_direction_amplification(lf: pl.LazyFrame) -> None:
    """Bytes/Pakete Richtung Server vs. Richtung Client, plus Amplification-Faktor."""
    df = (
        lf.with_columns([
            pl.coalesce(["ip.src", "ipv6.src"]).alias("src"),
            pl.coalesce(["ip.dst", "ipv6.dst"]).alias("dst"),
        ])
        .with_columns(
            pl.when(pl.col("src") == SERVER_IP)
            .then(pl.lit("outbound"))  # Server -> Client (Response)
            .when(pl.col("dst") == SERVER_IP)
            .then(pl.lit("inbound"))  # Client -> Server (Request)
            .otherwise(pl.lit("other"))
            .alias("direction")
        )
        .group_by("direction")
        .agg([
            pl.len().alias("packets"),
            pl.col("frame.len").sum().alias("bytes"),
        ])
        .collect()
    )

    row = {r["direction"]: r for r in df.to_dicts()}
    bytes_in = row.get("inbound", {}).get("bytes", 0)
    bytes_out = row.get("outbound", {}).get("bytes", 0)

    print(f"Bytes inbound (Client->Server)  : {bytes_in:>14,}")
    print(f"Bytes outbound (Server->Client) : {bytes_out:>14,}")
    if bytes_in > 0:
        print(f"Amplification factor (out/in)  : {bytes_out / bytes_in:>14.2f}")
    else:
        print("Amplification factor (out/in)  :          n/a (keine Inbound-Bytes)")

    del df
    gc.collect()


def metric_amplification_classification(lf_coap: pl.LazyFrame, plot_dir: Path) -> None:
    """
    Klassifiziert CoAP-Requests in simple / observer / group_request / not_identifiable.

    Reihenfolge der Regeln (erste zutreffende Regel gewinnt):
      1. group_request   : Zieladresse des Requests ist Multicast
      2. observer         : Observe-Option im Request gesetzt
      3. simple            : es existiert eine (via Token+Client-IP korrelierte)
                             Response, die groesser ist als der Request
      4. not_identifiable : keine korrelierte Response gefunden bzw. Response
                             nicht groesser als der Request
    """
    requests_df = (
        lf_coap.filter(pl.col("coap.code").is_in(list(COAP_REQUEST_CODES.keys())))
        .with_columns([
            pl.coalesce(["ip.src", "ipv6.src"]).alias("client_ip"),
            pl.coalesce(["ip.dst", "ipv6.dst"]).alias("server_ip"),
        ])
        .select([
            "frame.time_epoch", "client_ip", "server_ip", "coap.token",
            "coap.opt.observe", "frame.len",
        ])
        .rename({
            "frame.time_epoch": "req_time",
            "frame.len": "req_len",
            "coap.opt.observe": "req_observe",
        })
        .sort("req_time")
        .collect()
    )

    responses_df = (
        lf_coap.filter(pl.col("coap.code") >= 64)
        .with_columns([
            pl.coalesce(["ip.dst", "ipv6.dst"]).alias("client_ip"),
        ])
        .select(["frame.time_epoch", "client_ip", "coap.token", "frame.len"])
        .rename({"frame.time_epoch": "resp_time", "frame.len": "resp_len"})
        .sort("resp_time")
        .collect()
    )

    joined = requests_df.join_asof(
        responses_df,
        left_on="req_time",
        right_on="resp_time",
        by=["coap.token", "client_ip"],
        strategy="forward",
        tolerance=RESPONSE_CORRELATION_TOLERANCE_S,
    )

    is_multicast = pl.col("server_ip").str.starts_with(IPV4_MULTICAST_PREFIX) | pl.col(
        "server_ip"
    ).str.starts_with(IPV6_MULTICAST_PREFIX)

    joined = joined.with_columns(
        pl.when(is_multicast)
        .then(pl.lit("group_request"))
        .when(pl.col("req_observe").is_not_null())
        .then(pl.lit("observer"))
        .when((pl.col("resp_len").is_not_null()) & (pl.col("resp_len") > pl.col("req_len")))
        .then(pl.lit("simple"))
        .otherwise(pl.lit("not_identifiable"))
        .alias("amplification_type")
    )

    summary = (
        joined.group_by("amplification_type")
        .agg(pl.len().alias("count"))
        .sort("count", descending=True)
    )

    labels = summary["amplification_type"].to_list()
    values = summary["count"].to_list()
    total = sum(values)

    print("\nCoAP Amplification Attack Classification (heuristisch):")
    for label, value in zip(labels, values):
        print(f"  {label:<18}: {value:>10,} ({value / total:.2%})")

    stacked_single_bar(
        labels, values, total,
        title="CoAP Amplification Attack Classification",
        xlabel="Requests",
        plot_dir=plot_dir, name="amplification_classification",
    )

    del requests_df, responses_df, joined, summary
    gc.collect()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    plot_dir = ensure_plot_folder()
    t_start = time.perf_counter()
    lf = load_data()
    t_load = time.perf_counter()
    print("Loading lf took", t_load - t_start, "seconds")
    
    print("=== General CoAP Share ===")
    lf_coap = metric_general_coap_share(lf)
    t_overview = time.perf_counter()
    print("Overview lf took", t_overview - t_load, "seconds")

    print("\n=== IP Protocol Distribution ===")
    metric_ip_protocol_distribution(lf, plot_dir)
    t_ip = time.perf_counter()

    print("\n=== Top Source IPs ===")
    metric_top_source_ips(lf, plot_dir)
    t_talkers = time.perf_counter()

    print("\n=== Direction / Amplification Factor ===")
    metric_direction_amplification(lf)
    t_load = time.perf_counter()

    print("\n=== CoAP Message Types ===")
    metric_coap_message_types(lf_coap, plot_dir)
    t_type = time.perf_counter()

    print("\n=== CoAP Code Distribution ===")
    metric_coap_code_distribution(lf_coap, plot_dir)

    print("\n=== CoAP Amplification Classification ===")
    metric_amplification_classification(lf_coap, plot_dir)

    del lf, lf_coap
    gc.collect()

    print(f"\nAlle Plots gespeichert unter: {plot_dir.resolve()}")


if __name__ == "__main__":
    main()
