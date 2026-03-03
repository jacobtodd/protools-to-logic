# Pro Tools to Logic Pro Converter

Convert a Pro Tools `.ptx` session file into formats that Logic Pro (or any other DAW) can open — without needing Pro Tools installed.

## What It Does

Decrypts and parses the proprietary Pro Tools binary session format, extracts every track, audio clip, and timeline position, then outputs:

| Script | Output | Open with |
|--------|--------|-----------|
| `ptx_to_aaf.py` | `.aaf` — Advanced Authoring Format | Logic Pro, Avid Media Composer, Premiere Pro, DaVinci Resolve |
| `ptx_to_reaper.py` | `.rpp` — Reaper project | Reaper (free at reaper.fm), then export AAF from there |

Audio files are **linked externally**, not embedded — the output files point to your existing audio on disk, so nothing is duplicated.

## Requirements

```bash
pip install pyaaf2
```

Python 3.9+ required. No other dependencies.

## Usage

Edit the path constants at the top of whichever script you want to run:

```python
SESSION_DIR = Path("/path/to/your/session/folder")
PTX_FILE    = SESSION_DIR / "Your Session Name.ptx"
AUDIO_DIR   = SESSION_DIR / "Audio Files"
```

Then run:

```bash
# Generate an AAF (recommended — Logic Pro opens this directly)
python3 ptx_to_aaf.py

# Or generate a Reaper project
python3 ptx_to_reaper.py
```

Output files are written into the same folder as your `.ptx`.

**In Logic Pro:** `File → Open` and select the `.aaf`. Logic will ask where the audio lives — point it at your `Audio Files` folder.

## What Gets Preserved

- All track names
- All audio clip positions (sample-accurate)
- Source file offset per clip (where in the audio file the clip starts)
- Clip length
- Silence gaps between clips (filled with AAF Filler segments)

## Compatibility

Tested with **Pro Tools 10–12** session files (`.ptx`). The decryption algorithm differs slightly for Pro Tools 5–9 (`.pts`) sessions — that format uses a different XOR multiplier and key indexing, and is not currently handled.

Audio files in **RF64/MBWF format** (the 64-bit WAV extension that Pro Tools uses for large files) are fully supported.

## Limitations

- MIDI tracks are not extracted — audio only
- Automation, plug-in settings, sends, and routing are not transferred (these are DAW-specific and not representable in AAF)
- Region-to-track assignment is name-based (e.g. a region named `Vocals_01` is placed on a track named `Vocals`). This works reliably for standard Pro Tools session layouts but may miss clips if your naming convention is non-standard
- Any clips that can't be matched to a file on disk are replaced with silence

## How It Works

Pro Tools `.ptx` files are XOR-encrypted binary files built from a recursive block structure. Each block has a type, size, and content type field. Specific content types carry audio file lists, track names, region definitions, and three-point timing data (source offset, length, timeline position — all in samples).

The decryption key is derived from two bytes in the file header using a modular inverse calculation. Once decrypted, the block tree is walked to extract the session data, which is then used to build either a Reaper RPP (plain text) or an AAF (structured binary via pyaaf2).

## Inspiration & Credit

The PTX format reverse engineering in this project is built on top of the incredible foundational work done by **Damien Zammit** in the [ptformat](https://github.com/dammit/ptformat) library — an open-source C++ parser for Pro Tools session files.

Key algorithms sourced from ptformat:
- XOR decryption (`gen_xor_delta`, key table construction, per-byte key indexing)
- Block structure layout (ZMARK sentinel, type/size/content fields, recursive child parsing)
- Three-point timing encoding (variable-byte little-endian encoding of source offset, length, and timeline position)

Without ptformat's documentation and source code, the binary format would have been essentially opaque. Go give that repo a star.

## License

Non-Commercial Use Only. Free to use, modify, and share for personal or educational purposes. You may not sell this software or use it for any commercial purpose. See [LICENSE](LICENSE) for full terms.
