// GENERATED FILE — edit by regenerating, not by hand.
//
// scripts/generate-fallback-peers rewrites this file on the release path
// (#161): it resolves the mainnet DNS seeds, dials candidates with the same
// PeerConnection the app uses — whose handshake already refuses any peer not
// advertising NODE_COMPACT_FILTERS — and keeps a /16-spread selection, checked
// by the same `PeerEndpoint.netblock` the pool's diversity policy uses.
//
// The committed copy is the last verified generation and the build's fallback;
// a release regenerates so freshness tracks releases rather than memory.
// `FallbackPeerListTests` validates this file on every CI run.
//
// What this is not, recorded so it is not over-claimed: the list inherits
// whatever the generating host could see, and generation is not reproducible —
// two runs give different lists. The generation log is kept as a release
// artifact so the list is auditable even though it is not reproducible.
//
// Generation: 2026-08-25T00:42:03Z, 42 peers verified, median reported
// tip 963930.
extension NetworkParams {
    static let generatedMainnetFallbackPeers: [PeerEndpoint] = [
        PeerEndpoint(host: "103.193.138.6", port: 8333),  // /Satoshi:29.3.0/Knots:20260507/
        PeerEndpoint(host: "108.233.254.177", port: 8333),  // /Satoshi:29.3.0/Knots:20260508/
        PeerEndpoint(host: "109.226.191.224", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "12.11.29.34", port: 8333),  // /Satoshi:31.99.0/
        PeerEndpoint(host: "141.224.197.193", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "142.114.30.4", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "152.236.12.149", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "176.126.75.134", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "176.199.86.128", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "176.84.41.83", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "178.61.141.198", port: 8333),  // /Satoshi:29.2.0/
        PeerEndpoint(host: "180.68.238.158", port: 8333),  // /Satoshi:29.4.0/
        PeerEndpoint(host: "186.226.151.18", port: 8333),  // /Satoshi:27.1.0/
        PeerEndpoint(host: "2001:470:1f08:4db::2", port: 8333),  // /Satoshi:31.1.0(2)/
        PeerEndpoint(host: "2001:5a8:4164:7a00:be60:b5aa:22f0:d1cb", port: 8333),  // /Satoshi:31.99.0/
        PeerEndpoint(host: "2001:bc8:1da0:1:46a8:42ff:fe1b:3516", port: 8333),  // /Satoshi:30.2.0/
        PeerEndpoint(host: "201.211.122.154", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "201.219.78.6", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "203.56.149.66", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "216.237.253.188", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "217.164.243.184", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "217.198.136.37", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "223.25.71.139", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "24.141.241.54", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "2406:da12:ce1:f000:d627:d988:93d0:5002", port: 8333),  // /Satoshi:29.1.0/
        PeerEndpoint(host: "2a04:52c0:133:7eb2::1337", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "38.40.110.66", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "5.135.142.93", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "50.5.231.228", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "67.68.83.63", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "74.209.75.75", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "75.84.8.48", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "79.19.69.237", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "82.66.107.156", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "83.78.167.200", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "86.138.250.250", port: 8333),  // /Satoshi:30.2.0/
        PeerEndpoint(host: "88.0.22.163", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "88.84.223.30", port: 8333),  // /Satoshi:27.0.0/
        PeerEndpoint(host: "89.245.8.215", port: 8333),  // /Satoshi:31.0.0/
        PeerEndpoint(host: "93.186.3.158", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "97.186.20.14", port: 8333),  // /Satoshi:31.1.0/
        PeerEndpoint(host: "98.36.176.14", port: 8333),  // /Satoshi:31.0.0/
    ]
}
