# integrity_monitor

A small file integrity monitor written in Go, built to learn the language. Walks a directory tree, hashes every file with SHA-256, stores a baseline, and reports anything that changed since. Inspired by Tripwire, minus the policy language and signed database.

## Usage

```
integrity_monitor baseline <dir> [manifest]
integrity_monitor verify <dir> [manifest]
```

`baseline` snapshots the directory into a manifest, `verify` diffs the directory against it and prints one line per change. `manifest` defaults to `.integrity.json` in the current directory, purposely outside the monitored tree:

```
MODIFIED: a.txt
MISSING:  sub/b.txt
ADDED:    new.txt
```

`verify` exits 0 when nothing changed and 1 when something did, so a cronjob or scheduled task can easily act on the exit code.

## Notes

The `baseline` stores a SHA-256 hash, size, and mtime per file. `verify` checks size and mtime first since they're cheap, and flags the file if either differs. If both match it still gets rehashed, that's the only way to catch silent corruption, changed bytes with the same size and mtime.

Manifest keys use forward slashes so Windows and Linux agree. Baselines still aren't portable across machines though, a plain copy resets mtimes and everything flags as modified.

## Known constraints

This was a short project to learn Go, not something you would use on a real system, especially when tools like Tripwire exist. The big difference is anyone who can tamper with a file can usually edit the manifest to match, and verify won't catch it. If I kept going:

- Sign the manifest (HMAC) so it can't be edited to match tampering
- Real time watching (fsnotify) instead of re-running verify by hand
- Exclude certain patterns and a config file
- Write actual tests

## Build

```
go build
```

Cross-compile for a Raspberry Pi:

```
GOOS=linux GOARCH=arm64 go build
```
