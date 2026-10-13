[Back to main README](../../README.md)

# Header checkpoint derivation

`winnow-debug generate checkpoint` derives the mainnet header checkpoint
from a genesis-validated header file. This development tool shares the
`winnow-debug` executable and is not part of the shipping app.

Run from the repository root:

```sh
swift run winnow-debug generate --help
scripts/refresh-checkpoint ~/…/mainnet/headers.bin [height]
```

Choose a difficulty-period boundary (`height % 2016 == 0`) with at least
2,000 later headers available in the input. The tool rejects a mid-period
height. The current checkpoint is 959,616.

`checkpoint` truncates a genesis-rooted `headers.bin` to the wanted height
and loads the copy through `HeaderChain` itself, so every header is
proof-of-work-checked by the code the app runs, then prints the constant as a
paste-ready literal for `NetworkParams.swift`. It then proves the shipped
claim in-process: a chain started from the derived checkpoint connects the
next 2,000 real headers and must reach the same tip, height and cumulative
work as the genesis-rooted chain; disagreement exits non-zero. `--vector-out`
writes those 2,000 headers, one per line as hex, which is how
`Tests/WalletCoreTests/Vectors/mainnet-headers-959617-961616.txt` is made and
how `HeaderChainTests` replays real headers past the checkpoint on every
CI run. Deriving the chainwork itself still needs the full file, so that part
remains release-time only.

Offline checkpoint tests live in `Tests/ToolsTests/GenerateTests.swift`.
Peer discovery uses manual peers, saved peers, the census list each release
ships (`scripts/import-census`), and DNS seeds. No peer list is generated.
