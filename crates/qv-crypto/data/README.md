# Embedded data

These files are compiled into `qv-crypto` byte for byte. The crate checks
each file's SHA-256 before first use and fails closed on a mismatch, and unit
tests pin the same hashes. Do not edit, reformat or re-save them; `.gitattributes`
disables line-ending conversion for them.

| File | Use | Source | Licence | SHA-256 |
|------|-----|--------|---------|---------|
| `eff_large_wordlist.txt` | Passphrase generator, `eff-large` (spec 0010 §2.2) | <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>, from "EFF's New Wordlists for Random Passphrases" (Joseph Bonneau, Electronic Frontier Foundation, 2016) | CC BY 3.0 US, © Electronic Frontier Foundation | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` |
| `bip39-english.txt` | Recovery phrase (spec 0002 §4) | <https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt> (identical to the copy in Trezor's `python-mnemonic`) | MIT (BIP 39: "This BIP falls under the MIT License") | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |

Format: `eff_large_wordlist.txt` has 7,776 lines of `ddddd<TAB>word` (dice
numbers `11111`–`66666` in order). `bip39-english.txt` has 2,048 lines of one
word each, sorted. Both use LF line endings, including after the last line.
