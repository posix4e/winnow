[Back to main README](../../../../README.md)

# Peer discovery and selection

The wallet needs reachable peers and a way to compare their answers.
Seed resolution, diversity rules, pooling, and peer persistence live together
here so discovery and admission follow one policy.

[FilterSync](../Filters/README.md) and
[AppModel](../../../WinnowApp/AppModel.swift) consume the pool.
The pool tries manual peers, previously connected peers, the census list the
app was built with, and DNS seeds. `scripts/import-census` fetches the census
repository's `peers.json` into `build/census/` (with the census commit in
`peers-source.txt`) before XcodeGen runs, and project.yml bundles it into the
app (`CensusCatalog.bundled`); the app downloads no list. Tor- and I2P-only
routing draw their onion and I2P peers from the same list, so they need no
HTTP. A list that fails validation is not used, and DNS bootstrap starts
regardless. DNS uses DoH first, with system DNS when DoH yields no usable
addresses. The source ceiling remains: DNS alone can occupy two of the
three default slots; a manual peer or census provides another source.
Tor and I2P names have no netblock, so while clearnet is selected automatic
overlay peers together may not hold every slot either, and with Tor and I2P
both selected and clearnet off neither overlay may; a round that cannot fill
with a mix relaxes that rule for the next one.

[Peer policy tests](../../../../Tests/WalletCoreTests/Network/PeerPolicyTests.swift) cover
source classes, address ranges, persistence, and DNS replies.
[Pool tests](../../../../Tests/WalletCoreTests/Network/PeerPoolTests.swift) exercise
connection behavior. Diversity rules reduce concentration; they do not prove
that apparently different public peers have independent operators.
