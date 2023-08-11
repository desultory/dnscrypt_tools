# dnscrypt_tools

## Stamps

Code for processing DNSCrypt stamps, described in https://dnscrypt.info/stamps-specifications/

# Usage

Run './main.py', which will process a dnscrypt-proxy.toml.
The script's behavior is defined in 'config.toml'
By default it will write nftables rules to 'nftables.rules'

This ruleset is meant to be compatible with: https://wiki.gentoo.org/wiki/Nftables#Modular_Ruleset_Management
