# verso

Bitcoin wallet privacy analyzer. Given wallet descriptors, syncs transaction history via Bitcoin Core RPC or Esplora and runs 12 heuristic detectors to find privacy leaks.

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

## Screenshots 
<img width="1121" height="945" alt="image" src="https://github.com/user-attachments/assets/686cfba2-9120-40b9-aa87-0cefdf3e2d4e" />
<img width="1121" height="945" alt="image" src="https://github.com/user-attachments/assets/8bdc85b2-dce1-41b2-9c16-6eb02caf43b1" />
<img width="1191" height="726" alt="image" src="https://github.com/user-attachments/assets/b3562b3e-7976-45ab-9fd6-d729357889e0" />

## Inspiration 
This is basically a rewrite of [stealth](https://github.com/LORDBABUINO/stealth/) in a more unified way. 
