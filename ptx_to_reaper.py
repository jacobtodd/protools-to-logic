#!/usr/bin/env python3
"""
PTX → Reaper RPP Converter
Decrypts a Pro Tools 10-12 .ptx session, extracts tracks/regions/positions,
and writes a Reaper .rpp project that can be opened in Reaper (free) or
exported from there to AAF/Logic.

Usage:  python3 ptx_to_reaper.py /path/to/session/folder "Session Name"
        (or edit SESSION_DIR / PTX_FILE / AUDIO_DIR below)

Output: <Session Name>.rpp  in the same folder as the .ptx
"""

import sys, struct, os, re, time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# ── Configure your session here ───────────────────────────────────────────────
if len(sys.argv) >= 3:
    SESSION_DIR = Path(sys.argv[1])
    SESSION_NAME = sys.argv[2]
elif len(sys.argv) == 2:
    SESSION_DIR = Path(sys.argv[1])
    SESSION_NAME = SESSION_DIR.name
else:
    # Fallback: edit these paths manually
    SESSION_DIR  = Path("/path/to/your/session/folder")
    SESSION_NAME = "My Session"

PTX_FILE    = next(SESSION_DIR.glob("*.ptx"), SESSION_DIR / (SESSION_NAME + ".ptx"))
AUDIO_DIR   = SESSION_DIR / "Audio Files"
OUT_RPP     = SESSION_DIR / (PTX_FILE.stem + ".rpp")
SAMPLE_RATE = 44100   # overridden automatically from the session file

# ─────────────────────────────────────────────────────────────────────────────
# 1. DECRYPTION
# ─────────────────────────────────────────────────────────────────────────────

def gen_xor_delta(xv: int, mul: int, neg: bool) -> int:
    for i in range(256):
        if ((i * mul) & 0xff) == xv:
            return ((-i) & 0xff) if neg else i
    return 0

def decrypt_ptx(raw: bytes) -> bytes:
    xor_type  = raw[0x12]
    xor_value = raw[0x13]
    if xor_type == 0x01:
        xd = gen_xor_delta(xor_value, 53, False)
    else:  # 0x05  PT 10-12
        xd = gen_xor_delta(xor_value, 11, True)
    xxor = [(i * xd) & 0xff for i in range(256)]
    out  = bytearray(raw[:0x14])
    for i in range(0x14, len(raw)):
        key = i & 0xff if xor_type == 0x01 else (i >> 12) & 0xff
        out.append(raw[i] ^ xxor[key])
    return bytes(out)

# ─────────────────────────────────────────────────────────────────────────────
# 2. BLOCK PARSER
# ─────────────────────────────────────────────────────────────────────────────

def r2(d: bytes, p: int) -> int: return d[p] | (d[p+1] << 8)
def r4(d: bytes, p: int) -> int: return struct.unpack_from("<I", d, p)[0]

def parse_block(data: bytes, pos: int, parent_end: Optional[int] = None):
    if pos >= len(data) or data[pos] != 0x5a:
        return None
    end = parent_end if parent_end is not None else len(data)
    if pos + 9 > end:
        return None
    bt = r2(data, pos+1)
    bs = r4(data, pos+3)
    ct = r2(data, pos+7)
    if bt & 0xff00 or bs > 0x4000000:
        return None
    be = pos + 7 + bs
    if be > len(data):
        return None
    children = []
    i = 1
    while i < bs:
        c = parse_block(data, pos+i, be)
        if c:
            children.append(c)
            i += c[2] + 7
        else:
            i += 1
    return (bt, ct, bs, pos+7, children)   # (block_type, content_type, block_size, content_offset, children)

def find_top(data: bytes) -> list:
    blocks, pos = [], 0x14
    while pos < len(data):
        b = parse_block(data, pos)
        if b:
            blocks.append(b)
            pos += b[2] + 7
        else:
            pos += 1
    return blocks

def find_by_ct(blocks: list, ct: int) -> list:
    result = []
    for b in blocks:
        if b[1] == ct:
            result.append(b)
        result.extend(find_by_ct(b[4], ct))
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 3. THREE-POINT TIMING DECODE  (ptformat.cc algorithm, little-endian)
# ─────────────────────────────────────────────────────────────────────────────

def parse_three_point(data: bytes, j: int) -> Tuple[int, int, int]:
    """Returns (source_offset, length, start_on_timeline) all in samples."""
    if j + 10 >= len(data):
        return 0, 0, 0
    offsetbytes = (data[j+1] & 0xf0) >> 4
    lengthbytes  = (data[j+2] & 0xf0) >> 4
    startbytes   = (data[j+3] & 0xf0) >> 4
    base = j + 5

    def rle(pos, n):
        if n == 0 or pos + n > len(data):
            return 0
        v = 0
        for k in range(n):
            v |= data[pos+k] << (8*k)
        return v

    src_off = rle(base, offsetbytes)
    length  = rle(base + offsetbytes, lengthbytes)
    start   = rle(base + offsetbytes + lengthbytes, startbytes)
    return src_off, length, start

# ─────────────────────────────────────────────────────────────────────────────
# 4. EXTRACT SESSION DATA
# ─────────────────────────────────────────────────────────────────────────────

def extract_audio_files(data: bytes, top: list) -> List[str]:
    audio_files = []
    for b1004 in find_by_ct(top, 0x1004):
        if b1004[3] + 6 > len(data):
            continue
        nwavs = r4(data, b1004[3]+2)
        for b103a in [c for c in b1004[4] if c[1] == 0x103a]:
            pos = b103a[3] + 11
            n = 0
            while pos < b103a[3] + b103a[2] and n < nwavs:
                if pos + 4 > len(data):
                    break
                nl = r4(data, pos)
                if nl == 0 or nl > 512 or pos + 4 + nl > len(data):
                    pos += 4
                    continue
                fname = data[pos+4:pos+4+nl].decode("utf-8","replace").rstrip("\x00")
                pos += 4 + nl + 9   # +9: 4-byte file type + 5 padding
                audio_files.append(fname)
                n += 1
    return audio_files


def extract_track_names(data: bytes, top: list) -> List[str]:
    names = []
    for b1015 in find_by_ct(top, 0x1015):
        for b1014 in [c for c in b1015[4] if c[1] == 0x1014]:
            j = b1014[3] + 2
            if j + 4 > len(data):
                continue
            nl = r4(data, j)
            if nl == 0 or nl > 512 or j + 4 + nl > len(data):
                continue
            name = data[j+4:j+4+nl].decode("utf-8","replace").rstrip("\x00")
            names.append(name)
    return names


class Region:
    __slots__ = ("name", "start", "length", "src_offset", "wav_file")
    def __init__(self, name: str, start: int, length: int, src_offset: int):
        self.name       = name
        self.start      = start      # absolute sample position on timeline
        self.length     = length     # duration in samples
        self.src_offset = src_offset # offset within source file
        self.wav_file   = ""         # matched audio file path


def extract_regions(data: bytes, top: list) -> List[Region]:
    seen_offsets = set()
    regions = []
    for b2629 in find_by_ct(top, 0x2629):
        off = b2629[3]
        if off in seen_offsets:
            continue
        seen_offsets.add(off)
        j = off + 11   # into 0x2628 child block content (pascal string)
        if j + 4 >= len(data):
            continue
        nl = r4(data, j)
        if nl == 0 or nl > 512 or j + 4 + nl >= len(data):
            continue
        name = data[j+4:j+4+nl].decode("utf-8","replace").rstrip("\x00")
        j += nl + 4   # j += name.size() + 4  (ptformat convention)
        src_off, length, start = parse_three_point(data, j)
        if length > 0:
            regions.append(Region(name, start, length, src_off))
    return regions

# ─────────────────────────────────────────────────────────────────────────────
# 5. MATCH REGIONS TO AUDIO FILES
# ─────────────────────────────────────────────────────────────────────────────

def build_wav_index(audio_dir: Path) -> Dict[str, str]:
    """stem → full path for every wav file on disk."""
    index = {}
    for f in audio_dir.iterdir():
        if f.suffix.lower() in (".wav", ".aif", ".aiff"):
            index[f.stem.lower()] = str(f)
    return index

def match_regions_to_wavs(regions: List[Region], wav_index: Dict[str, str]):
    """Set region.wav_file for each region, trying multiple strategies."""
    for r in regions:
        key = r.name.lower()
        if key in wav_index:
            r.wav_file = wav_index[key]
            continue
        # Strip trailing edition markers like "-01", "-02"
        base = re.sub(r"-\d+$", "", key)
        if base in wav_index:
            r.wav_file = wav_index[base]
            continue
        # Try prefix match
        for stem, path in wav_index.items():
            if stem.startswith(key) or key.startswith(stem):
                r.wav_file = path
                break

# ─────────────────────────────────────────────────────────────────────────────
# 6. GROUP REGIONS INTO TRACKS
# ─────────────────────────────────────────────────────────────────────────────

def assign_regions_to_tracks(
    track_names: List[str],
    regions: List[Region],
    wav_index: Dict[str, str],
    session_start: int
) -> Dict[str, List[Region]]:
    """
    Best-effort track→region assignment using name matching.
    Returns {track_name: [sorted_regions]}.
    """
    track_dict: Dict[str, List[Region]] = {t: [] for t in track_names}

    # Build a quick lookup: region_name_lower → region
    region_map = {r.name.lower(): r for r in regions if r.wav_file}

    # For each track, find regions whose names START WITH the track base name
    for track in track_names:
        base = track.lower().rstrip()
        for r in regions:
            rn = r.name.lower()
            if rn == base or rn.startswith(base + "_") or rn.startswith(base + "."):
                if r not in track_dict[track]:
                    track_dict[track].append(r)

    # Any region with a wav file not yet assigned → put on its own track
    assigned = {r for lst in track_dict.values() for r in lst}
    orphans = [r for r in regions if r.wav_file and r not in assigned]
    if orphans:
        track_dict["_unassigned"] = orphans

    # Sort each track's regions by timeline position
    for track in track_dict:
        track_dict[track].sort(key=lambda r: r.start)

    return track_dict

# ─────────────────────────────────────────────────────────────────────────────
# 7. REAPER RPP GENERATION
# ─────────────────────────────────────────────────────────────────────────────

TRACK_COLOURS = [
    0x0094ff, 0xff6b35, 0x00c853, 0xff1744, 0xaa00ff,
    0x00bcd4, 0xffab40, 0x76ff03, 0xf50057, 0x448aff,
]

def samples_to_seconds(n: int, rate: int = SAMPLE_RATE) -> float:
    return n / rate

def write_rpp(
    out_path: Path,
    track_dict: Dict[str, List[Region]],
    session_start: int,
    sample_rate: int
):
    lines = []

    def L(s="", indent=0):
        lines.append("  " * indent + s)

    L("<REAPER_PROJECT 0.1 \"6.0/linux64\" {}>".format(int(time.time())))
    L("  TEMPO 120 4 4", 0)
    L("  SAMPLERATE {} 0 0".format(sample_rate), 0)
    L("  LOOP 0", 0)

    colour_idx = 0
    for track_name, regions in track_dict.items():
        if not regions:
            continue
        col = TRACK_COLOURS[colour_idx % len(TRACK_COLOURS)]
        colour_idx += 1

        L("<TRACK", 0)
        L('NAME "{}"'.format(track_name.replace('"', "'").strip()), 1)
        L("PEAKCOL {}".format(col | 0x01000000), 1)
        L("BEAT -1", 1)
        L("AUTOARM 1", 1)
        L("VOLPAN 1 0 -1 -1 1", 1)
        L("MUTESOLO 0 0 0", 1)
        L("IPHASE 0", 1)
        L("ISBUS 0 0", 1)
        L("BUSCOMP 0 0 0 0 0", 1)
        L("SHOWINMIX 1 0.6667 0.5 1 0.5 0 0 0", 1)
        L("SEL 0", 1)
        L("REC 0 0 1 0 0 0 0 0", 1)
        L("VU 2", 1)
        L("TRACKHEIGHT 0 0 0 0 0 0", 1)
        L("INQ 0 0 0 0.5 100 0 0 100", 1)
        L("NCHAN 1", 1)
        L("FX 1", 1)
        L("TRACKID {{{" + "00000000-0000-0000-0000-{:012x}".format(abs(hash(track_name)) & 0xffffffffffff) + "}}}", 1)

        for r in regions:
            if not r.wav_file:
                continue
            pos_s   = samples_to_seconds(max(0, r.start - session_start), sample_rate)
            len_s   = samples_to_seconds(r.length, sample_rate)
            srcoff_s= samples_to_seconds(r.src_offset, sample_rate)
            rel_path = os.path.relpath(r.wav_file, str(out_path.parent))

            L("<ITEM", 1)
            L("POSITION {:.10f}".format(pos_s), 2)
            L("SNAPOFFS 0", 2)
            L("LENGTH {:.10f}".format(len_s), 2)
            L("LOOP 0", 2)
            L("ALLTAKES 0", 2)
            L("FADEIN 0 0 0 0 0 0 0", 2)
            L("FADEOUT 0 0 0 0 0 0 0", 2)
            L("MUTE 0 0", 2)
            L("SEL 0", 2)
            L("IGUID {{{" + "00000000-0000-0000-0000-{:012x}".format(abs(hash(r.name+r.wav_file)) & 0xffffffffffff) + "}}}", 2)
            L("IID {}".format(abs(hash(r.name)) & 0x7fffffff), 2)
            L('NAME "{}"'.format(r.name.replace('"', "'")), 2)
            L("VOLPAN 1 0 1 -1", 2)
            L("SOFFS {:.10f}".format(srcoff_s), 2)
            L("PLAYRATE 1 1 0 -1 0 0.0025", 2)
            L("CHANMODE 0", 2)
            L("GUID {{{" + "00000000-0000-0000-0000-{:012x}".format(abs(hash(r.name)) & 0xffffffffffff) + "}}}", 2)
            L("<SOURCE WAVE", 2)
            L('FILE "{}"'.format(rel_path.replace("\\", "/")), 3)
            L(">", 2)
            L(">", 1)  # ITEM end

        L(">", 0)  # TRACK end

    L(">", 0)  # REAPER_PROJECT end

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"[rpp] Written: {out_path}")

# ─────────────────────────────────────────────────────────────────────────────
# 8. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("Reading PTX …")
    with open(PTX_FILE, "rb") as fh:
        raw = fh.read()

    print("Decrypting …")
    data = decrypt_ptx(raw)

    print("Parsing blocks …")
    top = find_top(data)
    print(f"  Top-level blocks: {len(top)}")

    # Session sample rate
    sr = SAMPLE_RATE
    for b in find_by_ct(top, 0x1028):
        if b[3] + 8 <= len(data):
            sr = r4(data, b[3]+4)
    print(f"Session sample rate: {sr} Hz")

    # Audio file registry
    print("Extracting audio files …")
    audio_files = extract_audio_files(data, top)
    print(f"  Registered: {len(audio_files)}")

    # Track names
    print("Extracting tracks …")
    track_names = extract_track_names(data, top)
    print(f"  Tracks: {len(track_names)}")

    # Regions
    print("Extracting regions …")
    regions = extract_regions(data, top)
    print(f"  Regions: {len(regions)}")

    # Determine session start: find the cluster of region starts and use the minimum
    all_starts = sorted(r.start for r in regions if r.start > 0 and r.length > sr)
    if len(all_starts) >= 2:
        # Use the median to anchor around the bulk of clips,
        # then take the minimum within 20% of the median (handles SMPTE offset sessions)
        import statistics
        median = statistics.median(all_starts)
        clustered = [s for s in all_starts if median * 0.80 <= s <= median * 1.20]
        if clustered:
            session_start = clustered[0]
        else:
            session_start = all_starts[0]
    elif all_starts:
        session_start = all_starts[0]
    else:
        session_start = 0
    print(f"Session start: {session_start} samples = {session_start/sr:.2f}s absolute")

    # Match regions to wav files on disk
    print("Building audio file index …")
    wav_index = build_wav_index(AUDIO_DIR)
    print(f"  WAV files on disk: {len(wav_index)}")

    print("Matching regions to audio files …")
    match_regions_to_wavs(regions, wav_index)
    matched = sum(1 for r in regions if r.wav_file)
    print(f"  Matched: {matched}/{len(regions)}")

    # Track assignment
    print("Assigning regions to tracks …")
    track_dict = assign_regions_to_tracks(track_names, regions, wav_index, session_start)

    # Summary
    tracks_with_content = {t: rs for t, rs in track_dict.items() if rs}
    print(f"\n── Track summary ──────────────────────────────────────────────────────")
    for t, rs in list(tracks_with_content.items())[:30]:
        rel = [(r.start - session_start)/sr for r in rs if r.start >= session_start]
        print(f"  '{t}'  ({len(rs)} clips)  "
              f"first_at={rel[0]:.1f}s" if rel else f"  '{t}'  ({len(rs)} clips)")

    # Write Reaper project
    print(f"\nWriting Reaper project …")
    write_rpp(OUT_RPP, track_dict, session_start, sr)

    print(f"\n── DONE ──────────────────────────────────────────────────────────────")
    print(f"Output: {OUT_RPP}")
    print()
    print("To open in Logic Pro:")
    print("  Option A: Open in Reaper (free at reaper.fm),")
    print("            then File → Export → AAF → open AAF in Logic.")
    print("  Option B: A Logic-compatible AAF can be generated by running")
    print("            python3 ptx_to_aaf.py  (uses the same parsed data)")
    print()
    print(f"Session: {sr} Hz  |  {matched} clips matched to {len(tracks_with_content)} tracks")

if __name__ == "__main__":
    main()
