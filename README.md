# MySQL Scanner

Port scanner CLI tool to detect MySQL running on a specified host and port. The scanner is meant to collect as much as it can from a single handshake without logging in.

## Building/Testing
Requires Go/Docker

- make build (Build binary and store at /bin/scanner)

- make test (Spins up mysql docker container to test against, test can take ~20 seconds)

## Usage
After building:

```./bin/scanner scan --host {host} (required) --port {port} (required) --timeout {timeout in milliseconds} (optional - set to 500ms by default)```

For more help or usage information

```./bin/scanner scan -h```

## Output
The scan will first output whether or not the specified port is open. If it is and it is a mysql instance it will return the following information about the instance

- MySQL Version
- MySQL Handshake Protocol
- Auth Plugin
- Character Set
- Status Flag

## References

MySQL Connection Phase - https://dev.mysql.com/doc/internals/en/connection-phase-packets.html

MySQL Character Sets - https://dev.mysql.com/doc/internals/en/character-set.html#packet-Protocol::CharacterSet

MySQL Status Flags - https://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags

Gnomock integration test package - https://github.com/orlangure/gnomock
