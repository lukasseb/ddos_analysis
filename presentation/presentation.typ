#import "@preview/touying:0.7.3": *
#import themes.university: *

#show: university-theme.with(
  aspect-ratio: "16-9",
  config-info(
    title: [Analysis of the CoAP data within a DDOS attack],
    subtitle: [Project Presentation],
    author: [Lukas Sebrantke at HAW Hamburg],
    date: datetime(day: 15, month: 07, year: 2026),
    logo: image("img/haw_logo.svg", width: 100pt),
  ),
)

#title-slide()

= Intro
== Motivation
- there was a DDOS-attack on the mobi3-server
- the data
- I'm currently working on CoAP at RIOT
- one of the protocols used for the attack was CoAP
$=>$ thats why the scope of my analysis is set to the CoAP data within the dataset
== Amplifications Attacks using CoAP
- Simple Amplification Attacks
- Amplification Attacks using Observe
- Amplification Attacks using Group Requests
== Measurement Question
#align(center + horizon)[

]

- The amplification factor and the bandwidth depend on the layer in the protocol stack that is used for the calculation. The amplification factor and bandwidth can e.g., be calculated using whole IP packets, UPD payloads, or CoAP payloads. The bandwidth decreases and the amplification factor typically increases higher up in the protocol stack. The bandwidth should be calculated using the layer that is considered to be under attack.

= Method

== TODO
- 779 GiB of data: _net/archive/ddos_data_
// - parsed with #link("https://www.wireshark.org/docs/man-pages/tshark.html")["tshark"]

= Plots


#bibliography("literature.bib")