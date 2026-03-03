#!/usr/bin/env python3
"""
PTX → AAF Converter
Decrypts a Pro Tools 10-12 .ptx session, extracts tracks/regions/positions,
and writes an AAF file that Logic Pro can import directly via File → Open.

Usage:  python3 ptx_to_aaf.py /path/to/session/folder "Session Name"
        (or edit SESSION_DIR / PTX_FILE / AUDIO_DIR below)

Output: <Session Name>.aaf  in the same folder as the .ptx
"""

import sys, struct, os, re, statistics
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
OUT_AAF     = SESSION_DIR / (PTX_FILE.stem + ".aaf")
SAMPLE_RATE = 44100   # overridden automatically from the session file

# ─────────────────────────────────────────────────────────────────────────────
# 1. DECRYPTION  (same as ptx_to_reaper.py)
# ─────────────────────────────────────────────────────────────────────────────

def gen_xor_delta(xv: int, mul: int, neg: bool) -> int:
    for i in range(256):
        if ((i * mul) & 0xff) == xv:
            return ((-i) & 0xff) if neg else i
    return 0

def decrypt_ptx(raw: bytes) -> bytes:
    xor_type  = raw[0x12]
    xor_value = raw[0x13]
    xd = gen_xor_delta(xor_value, 53, False) if xor_type == 0x01 \
         else gen_xor_delta(xor_value, 11, True)
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
    bt = r2(data, pos+1); bs = r4(data, pos+3); ct = r2(data, pos+7)
    if bt & 0xff00 or bs > 0x4000000:
        return None
    be = pos + 7 + bs
    if be > len(data):
        return None
    children = []; i = 1
    while i < bs:
        c = parse_block(data, pos+i, be)
        if c: children.append(c); i += c[2] + 7
        else: i += 1
    return (bt, ct, bs, pos+7, children)   # (block_type, content_type, block_size, content_offset, children)

def find_top(data: bytes) -> list:
    blocks, pos = [], 0x14
    while pos < len(data):
        b = parse_block(data, pos)
        if b: blocks.append(b); pos += b[2] + 7
        else: pos += 1
    return blocks

def find_by_ct(blocks: list, ct: int) -> list:
    result = []
    for b in blocks:
        if b[1] == ct: result.append(b)
        result.extend(find_by_ct(b[4], ct))
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 3. THREE-POINT TIMING
# ─────────────────────────────────────────────────────────────────────────────

def parse_three_point(data: bytes, j: int) -> Tuple[int, int, int]:
    if j + 10 >= len(data): return 0, 0, 0
    offsetbytes = (data[j+1] & 0xf0) >> 4
    lengthbytes  = (data[j+2] & 0xf0) >> 4
    startbytes   = (data[j+3] & 0xf0) >> 4
    base = j + 5
    def rle(pos, n):
        if n == 0 or pos + n > len(data): return 0
        v = 0
        for k in range(n): v |= data[pos+k] << (8*k)
        return v
    return rle(base, offsetbytes), rle(base+offsetbytes, lengthbytes), rle(base+offsetbytes+lengthbytes, startbytes)

# ─────────────────────────────────────────────────────────────────────────────
# 4. SESSION DATA EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_audio_files(data: bytes, top: list) -> List[str]:
    audio_files = []
    for b1004 in find_by_ct(top, 0x1004):
        if b1004[3] + 6 > len(data): continue
        nwavs = r4(data, b1004[3]+2)
        for b103a in [c for c in b1004[4] if c[1] == 0x103a]:
            pos = b103a[3] + 11; n = 0
            while pos < b103a[3] + b103a[2] and n < nwavs:
                if pos + 4 > len(data): break
                nl = r4(data, pos)
                if nl == 0 or nl > 512 or pos + 4 + nl > len(data):
                    pos += 4; continue
                fname = data[pos+4:pos+4+nl].decode("utf-8","replace").rstrip("\x00")
                pos += 4 + nl + 9
                audio_files.append(fname); n += 1
    return audio_files

def extract_track_names(data: bytes, top: list) -> List[str]:
    names = []
    for b1015 in find_by_ct(top, 0x1015):
        for b1014 in [c for c in b1015[4] if c[1] == 0x1014]:
            j = b1014[3] + 2
            if j + 4 > len(data): continue
            nl = r4(data, j)
            if nl == 0 or nl > 512 or j + 4 + nl > len(data): continue
            name = data[j+4:j+4+nl].decode("utf-8","replace").rstrip("\x00")
            names.append(name)
    return names

class Region:
    __slots__ = ("name", "start", "length", "src_offset", "wav_file")
    def __init__(self, name: str, start: int, length: int, src_offset: int):
        self.name       = name
        self.start      = start
        self.length     = length
        self.src_offset = src_offset
        self.wav_file   = ""

def extract_regions(data: bytes, top: list) -> List[Region]:
    seen = set(); regions = []
    for b2629 in find_by_ct(top, 0x2629):
        off = b2629[3]
        if off in seen: continue
        seen.add(off)
        j = off + 11
        if j + 4 >= len(data): continue
        nl = r4(data, j)
        if nl == 0 or nl > 512 or j + 4 + nl >= len(data): continue
        name = data[j+4:j+4+nl].decode("utf-8","replace").rstrip("\x00")
        j += nl + 4
        src_off, length, start = parse_three_point(data, j)
        if length > 0:
            regions.append(Region(name, start, length, src_off))
    return regions

def build_wav_index(audio_dir: Path) -> Dict[str, str]:
    index = {}
    for f in audio_dir.iterdir():
        if f.suffix.lower() in (".wav", ".aif", ".aiff"):
            index[f.stem.lower()] = str(f)
    return index

def match_regions_to_wavs(regions: List[Region], wav_index: Dict[str, str]):
    for r in regions:
        key = r.name.lower()
        if key in wav_index: r.wav_file = wav_index[key]; continue
        base = re.sub(r"-\d+$", "", key)
        if base in wav_index: r.wav_file = wav_index[base]; continue
        for stem, path in wav_index.items():
            if stem.startswith(key) or key.startswith(stem):
                r.wav_file = path; break

def assign_regions_to_tracks(track_names: List[str], regions: List[Region]) -> Dict[str, List[Region]]:
    track_dict: Dict[str, List[Region]] = {t: [] for t in track_names}
    for track in track_names:
        base = track.lower().rstrip()
        for r in regions:
            rn = r.name.lower()
            if (rn == base or rn.startswith(base + "_") or rn.startswith(base + ".")) \
               and r not in track_dict[track]:
                track_dict[track].append(r)
    assigned = {r for lst in track_dict.values() for r in lst}
    orphans  = [r for r in regions if r.wav_file and r not in assigned]
    if orphans: track_dict["_unassigned"] = orphans
    for t in track_dict: track_dict[t].sort(key=lambda r: r.start)
    return track_dict

# ─────────────────────────────────────────────────────────────────────────────
# 5. RF64 / WAV METADATA
# ─────────────────────────────────────────────────────────────────────────────

def parse_audio_info(path: str):
    """
    Returns (nframes, nchannels, sample_rate, bits_per_sample, block_align)
    Works with both standard WAV (RIFF) and RF64/MBWF files.
    """
    with open(path, 'rb') as f:
        magic = f.read(4)
        f.read(4)   # overall size (ignore)
        wave_id = f.read(4)
        if wave_id != b'WAVE':
            return None

        nframes_64 = None
        nchannels = nch = sample_rate = bits = block_align = None

        while True:
            chunk_id = f.read(4)
            if len(chunk_id) < 4: break
            sz_raw = f.read(4)
            if len(sz_raw) < 4: break
            sz = struct.unpack('<I', sz_raw)[0]

            if chunk_id == b'ds64':
                f.read(8)                                    # RIFF 64-bit size
                f.read(8)                                    # data 64-bit size
                nframes_64 = struct.unpack('<Q', f.read(8))[0]
                rest = sz - 24
                if rest > 0: f.read(rest)
            elif chunk_id == b'fmt ':
                fmt = f.read(min(sz, 40))
                (fmt_tag, nchannels, sample_rate,
                 avg_bps, block_align, bits) = struct.unpack_from('<HHLLHH', fmt)
                if sz > 16: f.read(sz - 16)
            elif chunk_id == b'data':
                if nframes_64 is None and bits and nchannels:
                    data_bytes = sz if sz != 0xFFFFFFFF else 0
                    nframes_64 = data_bytes // (nchannels * (bits // 8))
                break
            else:
                f.read(sz + sz % 2)

    if None in (nframes_64, nchannels, sample_rate, bits):
        return None
    return nframes_64, nchannels, sample_rate, bits, block_align or (nchannels * (bits // 8))

# ─────────────────────────────────────────────────────────────────────────────
# 6. AAF GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def write_aaf(out_path: Path, track_dict: Dict[str, List[Region]],
              session_start: int, sample_rate: int):
    import aaf2
    from aaf2.rational import AAFRational
    from aaf2.auid import AUID
    import pathlib, sys

    PCM_COMPRESSION = AUID('04020202-0000-0000-060e-2b3404010101')
    edit_rate = AAFRational(sample_rate, 1)

    # ── cache: wav_path → (SourceMob, MasterMob, nframes)
    file_mob_cache: Dict[str, tuple] = {}

    def make_network_locator(f, abs_path: str):
        loc = f.create.NetworkLocator()
        loc['URLString'].value = pathlib.Path(abs_path).as_uri()
        return loc

    def get_or_create_file_mobs(f, wav_path: str):
        if wav_path in file_mob_cache:
            return file_mob_cache[wav_path]

        info = parse_audio_info(wav_path)
        if info is None:
            return None
        nframes, nchannels, sr, bits, block_align = info

        # ── SourceMob (the physical file)
        src = f.create.SourceMob()
        src.name = Path(wav_path).name

        desc = f.create.PCMDescriptor()
        desc['SampleRate'].value         = AAFRational(sr, 1)
        desc['AudioSamplingRate'].value  = AAFRational(sr, 1)
        desc['Channels'].value           = nchannels
        desc['QuantizationBits'].value   = bits
        desc['BlockAlign'].value         = block_align
        desc['AverageBPS'].value         = sr * block_align
        desc['Length'].value             = nframes
        desc['Compression'].value        = PCM_COMPRESSION
        desc['Locator'].append(make_network_locator(f, wav_path))
        src.descriptor = desc

        src_slot = src.create_sound_slot(edit_rate=AAFRational(sr, 1))
        src_slot.slot_id = 1
        src_null = f.create.SourceClip(media_kind='sound', length=nframes)
        src_slot.segment.length = nframes
        src_slot.segment.components.append(src_null)
        f.content.mobs.append(src)

        # ── MasterMob (the reference level)
        mmob = f.create.MasterMob()
        mmob.name = Path(wav_path).stem
        m_slot = mmob.create_sound_slot(edit_rate=AAFRational(sr, 1))
        m_slot.slot_id = 1
        m_clip = f.create.SourceClip(
            media_kind='sound', length=nframes,
            mob_id=src.mob_id, slot_id=1, start=0)
        m_slot.segment.length = nframes
        m_slot.segment.components.append(m_clip)
        f.content.mobs.append(mmob)

        file_mob_cache[wav_path] = (src, mmob, nframes)
        return src, mmob, nframes

    print(f"[aaf] Opening {out_path} for writing …")
    with aaf2.open(str(out_path), 'w') as f:
        comp = f.create.CompositionMob()
        comp.name = "Let it Air Out"
        f.content.mobs.append(comp)

        slot_id = 1
        tracks_written = 0
        clips_written  = 0
        missing_files  = 0

        for track_name, regions in track_dict.items():
            if not regions: continue

            t_slot = comp.create_sound_slot(edit_rate=edit_rate)
            t_slot.slot_id = slot_id
            t_slot.name    = track_name
            slot_id       += 1

            fill_pos = 0   # running cursor in this track (samples from session_start)

            for region in regions:
                rel_start = region.start - session_start
                if rel_start < 0:
                    rel_start = 0   # clamp if somehow before session start

                # Gap → Filler
                if rel_start > fill_pos:
                    gap = rel_start - fill_pos
                    filler = f.create.Filler(media_kind='sound', length=gap)
                    t_slot.segment.components.append(filler)
                    fill_pos += gap

                if not region.wav_file:
                    # No audio found → silent placeholder
                    placeholder = f.create.Filler(media_kind='sound',
                                                   length=region.length)
                    t_slot.segment.components.append(placeholder)
                    fill_pos += region.length
                    missing_files += 1
                    continue

                result = get_or_create_file_mobs(f, region.wav_file)
                if result is None:
                    placeholder = f.create.Filler(media_kind='sound',
                                                   length=region.length)
                    t_slot.segment.components.append(placeholder)
                    fill_pos += region.length
                    missing_files += 1
                    continue

                _, mmob, file_nframes = result
                # Clamp src_offset and clip length to file bounds
                src_off = min(region.src_offset, max(0, file_nframes - 1))
                length  = min(region.length, file_nframes - src_off)
                if length <= 0: length = 1

                clip = f.create.SourceClip(
                    media_kind='sound',
                    length=length,
                    mob_id=mmob.mob_id,
                    slot_id=1,
                    start=src_off,
                )
                t_slot.segment.components.append(clip)
                fill_pos   += length
                clips_written += 1

            t_slot.segment.length = fill_pos
            tracks_written += 1

        print(f"[aaf] {tracks_written} tracks, {clips_written} clips written")
        if missing_files:
            print(f"[aaf] {missing_files} clips replaced with silence (file not found)")

    print(f"[aaf] Done → {out_path}")

# ─────────────────────────────────────────────────────────────────────────────
# 7. MAIN
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

    # Sample rate
    sr = SAMPLE_RATE
    for b in find_by_ct(top, 0x1028):
        if b[3] + 8 <= len(data): sr = r4(data, b[3]+4)
    print(f"  Sample rate: {sr} Hz")

    print("Extracting audio files …")
    audio_files = extract_audio_files(data, top)
    print(f"  Registered: {len(audio_files)}")

    print("Extracting tracks …")
    track_names = extract_track_names(data, top)
    print(f"  Tracks: {len(track_names)}")

    print("Extracting regions …")
    regions = extract_regions(data, top)
    print(f"  Regions: {len(regions)}")

    # Detect session start (cluster median approach)
    all_starts = sorted(r.start for r in regions if r.start > 0 and r.length > sr)
    if len(all_starts) >= 2:
        median = statistics.median(all_starts)
        clustered = [s for s in all_starts if median * 0.80 <= s <= median * 1.20]
        session_start = clustered[0] if clustered else all_starts[0]
    else:
        session_start = all_starts[0] if all_starts else 0
    print(f"  Session start: {session_start} samples = {session_start/sr:.2f}s")

    print("Building WAV index …")
    wav_index = build_wav_index(AUDIO_DIR)
    print(f"  WAV files on disk: {len(wav_index)}")

    print("Matching regions to audio files …")
    match_regions_to_wavs(regions, wav_index)
    matched = sum(1 for r in regions if r.wav_file)
    print(f"  Matched: {matched}/{len(regions)}")

    print("Assigning regions to tracks …")
    track_dict = assign_regions_to_tracks(track_names, regions)

    tracks_with_content = {t: rs for t, rs in track_dict.items() if rs}
    print(f"  Tracks with content: {len(tracks_with_content)}")

    print("\nWriting AAF …")
    write_aaf(OUT_AAF, tracks_with_content, session_start, sr)

    print(f"\n── DONE ─────────────────────────────────────────────────────────")
    print(f"Output:  {OUT_AAF}")
    print()
    print("In Logic Pro:  File → Open  and select the .aaf file.")
    print("               Logic will ask where to copy the audio — point it")
    print("               at the 'Audio Files' folder alongside the .ptx.")

if __name__ == "__main__":
    main()
