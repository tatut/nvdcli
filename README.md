# nvdcli

![test workflow](https://github.com/tatut/nvdcli/actions/workflows/test.yml/badge.svg)

nvdcli is a tool to download and query a local cache of NVD vulnerability data.
It is blazing fast (because it's just sqlite under the hood).

## Arguments

Options:
* `--nvd-api-key` [NVD API](https://nvd.nist.gov/developers/start-here) key to use when building/updating database
* `--db-file` filename to use for database, defaults to `nvd.data`
* `--output` output format (defaults to `short`)

Output formats:
* `id` show CVE id only, one per line, for shell scripting tool use
* `short` (default) show CVE id, severity and (truncated) description
* `verbose` show all information
* `json` output the raw JSON (for tools)

Commands:
* `build` build new database from scratch (takes a long time, see releases for cached starting point)
* `update` fetch updates after the latest modification time
* `get` get a record JSON
* `show` show a record in human readable format
* `search` free text search from records
* `q` (or `query`) advanced search


## Advanced search

Advanced search takes multiple filter arguments and constructs an NVD query.

Supported filters:
* `match:<keyword>` free text search from id or description
* `sev:<severity>` where severity matches (eg, `sev:HIGH`)
* `score:<op?><num>` where impact score is smaller/greater/exactly num (eg. `score:>9.0` search scores above 9) if no op, searches exact match
* ...more coming soon...

For example to search CVEs for liferay that have an impact score larger than 7, you would run: `nvdcli q "score:>7" match:liferay`
