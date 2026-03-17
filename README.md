# verso

Bitcoin wallet privacy analyzer. Given wallet descriptors, syncs transaction history via Bitcoin Core RPC or Esplora and runs 12 heuristic detectors to find privacy leaks.

Inspired by [stealth](https://github.com/LORDBABUINO/stealth/).

## Crates

| Crate | Description |
|-------|-------------|
| `verso-core` | Library — scan engine, detectors, and report types. Use this to integrate verso into your own tools. |
| `verso-cli` | Command-line interface. |
| `verso-app` | Desktop GUI (Dioxus). |

## Detectors

Address reuse, common-input-ownership (CIOH), dust outputs, dust spending, change detection, consolidation patterns, script type mixing, cluster merge, UTXO age analysis, exchange origin, taint analysis, behavioral patterns.

## Usage

```
verso <DESCRIPTOR> [DESCRIPTOR] [OPTIONS]
```

Supports Esplora and Bitcoin Core RPC backends.

```
verso "wpkh(xpub.../0/*)" "wpkh(xpub.../1/*)" --network mainnet --backend esplora
```

## Build

```
cargo build --release
```
