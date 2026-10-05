# Configuration

## Desktop backend

The client uses `https://localhost:5059` on first launch. In the client, open Preferences and enter the base URL for the server. Do not include a `/tunnel` path suffix. Client preferences are stored in a local `config.json` file.

The client pins the server certificate using the value in `Client/Lib/GeneratedCertificatePin.cs`. Generate a development certificate with `python gen_cert.py` from the `Server` directory; the script writes the SHA-256 fingerprint to that C# file. Rebuild the client after generating or replacing the certificate. Keep the private key at `Server/data/key.pem` secret.

## Server credentials

Copy `Server/data/config.example.yaml` to `Server/data/config.yaml`. Add only credentials for services you are authorized to use. The file is ignored by Git. Never commit API keys or put them in client settings.

The server can run without upstream API keys, but services that require keys will return configuration errors until credentials are configured.

## Internal DNS and computer names

For private IP reverse lookups, the server uses the operating system's configured DNS resolver by default. To specify internal DNS resolvers, set `CSOTOOLBOX_INTERNAL_DNS` to a comma-separated list of addresses, for example `192.0.2.53,192.0.2.54` (replace these documentation-only addresses with resolvers you control).

Computer identifiers in the generic `PCOMP-1234567` or `PCOMP_1234567` format are resolved under `example.invalid` by default. Set `CSOTOOLBOX_PCOMPUTER_DOMAIN` to a domain you control if this feature is needed. The default suffix is intentionally non-resolving.

## Private network annotations

Edit `Server/data/ipdb.csv` to describe private IPv4 ranges used in your own environment. Each row contains a CIDR, usage label, location label, and comment. The committed data uses generic examples; do not put employee names, office layouts, or sensitive infrastructure details in a public copy.
