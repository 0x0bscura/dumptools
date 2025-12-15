# dumptools

Fast Rust CLI for threat and intelligence analysts to convert and scan credential dumps.

```
   ___                ______          __  
  / _ \__ ____ _  ___/_  __/__  ___  / /__
 / // / // /  ' \/ _ \/ / / _ \/ _ \/ (_-<
/____/\_,_/_/_/_/ .__/_/  \___/\___/_/___/
               /_/                         
dumptools – fast conversion and scanning for credential dumps
made by 0bscura with <3
```

## Commands
- `dumptools convert`: normalize raw `*.txt` dumps into grouped JSON Lines for NoSQL ingestion.
- `dumptools scan`: search large text dumps for indicators with live status output.

## Convert output format
Each credential group becomes one JSON document:
```json
{
  "_id": "random-unique-id",
  "email": "john.doe@example.com",
  "passwords": [
    {
      "value": "P@ssw0rd!",
      "for": "example.com",
      "source": "Collection #1/01.txt"
    }
  ]
}
```
- `_id`: randomly generated unique identifier.
- `email`: primary account identifier.
- `passwords`: list of password occurrences with the target service and source file.

## Installation
Install the binary with Cargo:
```bash
cargo install --path .
```

### `convert`
Convert credential lines (e.g., `email:password[:site]`) from `*.txt` files into JSONL grouped by email.
```bash
dumptools convert --path /path/to/dumps --output out.jsonl
```
- `--path, -p`: directory to read `*.txt` files recursively (default: current directory).
- `--output, -o`: destination file (stdout if omitted).
- `--delimiter, -d`: field separator, default `:`.
- `--site-from`: constant to use for the `for` field when none is present per line.

### `scan`
Search dumps for one or more needles with live status output.
```bash
dumptools scan "alice@example.com" --path /path/to/dumps -o hits.jsonl
dumptools scan indicators.txt --file --path /path/to/dumps -o hits.jsonl
```
- `needle`: string to search for, or a file of needles when `--file` is set.
- `--path, -p`: directory to scan recursively for `*.txt` (default: current directory).
- `--file, -f`: treat `needle` as a file containing search strings (one per line).
- `--case-sensitive, -s`: opt into case-sensitive matching (default: insensitive).
- `--threads, -t`: number of worker threads (default: detected cores).
- `--output, -o` (required): write matches to a JSONL file with `line`, `file`, `needle`, `timestamp`.
- Needle files are de-duplicated using the active case-sensitivity mode (default: insensitive).
- Colour output auto-disables when not running on a TTY.
- Extend by adding parsers for more dump formats and additional enrichment (e.g., domain inference).
