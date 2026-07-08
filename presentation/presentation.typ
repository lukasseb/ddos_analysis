#import "@preview/touying:0.7.3": *
#import themes.university: *

#show: university-theme.with(
  aspect-ratio: "16-9",
  config-info(
    title: [Analysis of the DDOS attack on mobi3],
    subtitle: [Project Presentation],
    author: [Lukas Sebrantke at HAW Hamburg],
    date: datetime(day: 08, month: 07, year: 2026),
    logo: image("img/haw_logo.svg", width: 100pt),
  ),
)

#title-slide()

#outline()

= Opening

= Background

=== Simple Amplification Attacks

=== Amplification Attacks using Observe

=== Amplification Attacks using Group Requests

= TODO: eine spezifische Frage

The amplification factor and the bandwidth depend on the layer in the protocol stack that is used for the calculation. The amplification factor and bandwidth can e.g., be calculated using whole IP packets, UPD payloads, or CoAP payloads. The bandwidth decreases and the amplification factor typically increases higher up in the protocol stack. The bandwidth should be calculated using the layer that is considered to be under attack.

= Methodology


== How was the data stored
- 779 GiB of data

== How was the data parsed
- based upon the different Amplification Attacks within CoAP, the following field of the .pcap-files were parsed:

== How was the data processed (1)

== How was the data processed (2)

== How was the data processed (3)

= Evaluation

= Closing

== Conclusion

== Discussion