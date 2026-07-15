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

#show outline: set text(size: 0.8em)
#outline()

= Intro
== Motivation
#v(2em)
- starting at the 25th of August 2025 there was a DDOS attack on mobi3
#v(0.5em)
- part of that multi-protocol DDOS attack was CoAP traffic
#v(0.5em)
- CoAP is also the focus of my work at RIOT and in other modules

== Amplifications Attacks using CoAP
#v(2em)
- based upon the IRTF draft: _Amplification Attacks Using the Constrained Application Protocol (CoAP)_ @irtf-t2trg-amplification-attacks-05
#v(0.5em)
- are a type of reflection-based volumetric DDoS/DoS attacks
#v(0.5em)
- TODO: which amplification factor, see @irtf-t2trg-amplification-attacks-05

#pagebreak()
#v(2em)
- Simple Amplification Attacks
#v(0.5em)
- Amplification Attacks using the Observe Option
#v(0.5em)
- Amplification Attacks using Group Requests
#v(0.5em)
- Amplification Attacks using Group Requests and the Observe Option

== Research Question
#align(center+horizon)[
  #text(size: 2em)[
    Are the 4 types of amplification attacks recognizable in the DDOS attack on mobi3?
  ]
]

== Method
#v(2em)
- 779 GiB of data: _net/archive/ddos_data_
#v(0.5em)
- only a subset of data was used (next slide)
#v(0.5em)
- parsed with #link("https://www.wireshark.org/docs/man-pages/tshark.html")[_tshark_]
#v(0.5em)
- _general_data_set_ and _coap_data_set_

= Plots
== General Analysis
#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/overview.png", width: 90%),
    caption: "Overview of analyzed data"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/packets_direction.png", width: 100%),
    caption: "Share of Packet Directions"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/ip_proto_distr.png", width: 100%),
    caption: "Share of IP Protocols"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/top_source_ips_bytes.png", height: 90%),
    caption: "Top Talkers"
  )
]

== CoAP specific Analysis
#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_overview.png", width: 80%),
    caption: "Overview of CoAP data"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_ip_proto_distr.png", width: 100%),
    caption: "Share of IP Protocols of CoAP packets"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_message_types.png", width: 100%),
    caption: "Share of CoAP Message Types"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_code_distribution.png", width: 100%),
    caption: "Share of CoAP Codes"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_packet_size_distribution.png", width: 90%),
    caption: "Packet Sizes within CoAP"
  )
]

#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_top20_ip_src.png", height: 90%),
    caption: "Top Talkers of CoAP"
  )
]

= Outro
== Answer to the Research Question
#align(center+horizon)[
  #figure(
    image("../plots/batch_1_1000/coap/coap_amplification_category_bar.png", width: 90%),
    caption: "Amplification Attacks Categories"
  )
]

#align(center+horizon)[
  #text(size: 2em)[
    Yes, but in the attack only Simple and Observe were used!
  ]
]

== Other Findings
#v(2em)
- only around 0.7% of the DDOS attack packets consists of CoAP packets
#v(0.5em)
- as expected is most of the data transported by UDP
#v(0.5em)
- as expected are most of CoAP packets of method GET in a message of type ACK  
#v(0.5em)
- no DTLS was found

== Literature
#v(2em)
#show bibliography: set text(size: 0.8em)
#bibliography("literature.bib", title: none, style: "ieee")
