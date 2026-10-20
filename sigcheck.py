#!/usr/bin/env python3
"""
sigcheck - file signature checker.

Reads the first bytes of every file (its "magic number"), works out what the
file really is, and flags files whose extension lies: an executable named
.jpg, a ZIP named .pdf, a .docx that's really an old .doc, a .png full of
random bytes. Also flags data hidden after the end of an image, PDF or ZIP,
Office files with macros, PDFs with JavaScript or launch actions, archives
that carry executables, double extensions and right-to-left override tricks.

Standard library only. Python 3.8+.

https://github.com/Landull/sigcheck
"""

import argparse
import csv
import fnmatch
import hashlib
import io
import json
import math
import os
import re
import stat
import struct
import sys
import zipfile
from collections import Counter

__version__ = "1.0.0"

HEAD_SIZE = 0x9800          # far enough to see an ISO 9660 volume descriptor
CHUNK = 1 << 20
DEFAULT_MAX_SCAN = 256 * 1024 * 1024

# Categories that can run code when opened.
EXEC_CATS = {"executable", "script", "shortcut", "installer", "help"}

RISKY_EXT = {
    "exe", "msi", "msix", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "lnk", "jar", "dll", "cpl", "iso", "img", "vhd", "vhdx", "dmg",
    "pkg", "app", "command", "sh", "apk", "appx", "docm", "xlsm", "pptm", "one", "reg",
    "url", "library-ms", "chm", "pif", "msc", "gadget", "inf", "sys", "elf", "py",
}

DECOY_EXT = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg",
    "png", "gif", "bmp", "mp3", "mp4", "mov", "avi", "wav", "zip", "csv", "odt", "html",
}

# Extensions used for too many unrelated formats to judge.
AMBIGUOUS_EXT = {
    "", "dat", "bin", "db", "img", "sys", "o", "out", "run", "raw", "cap", "dmp", "data",
    "tmp", "log", "cache", "bak", "old", "001", "dd", "mem", "vmem", "pf", "sav", "mod",
    "thm", "tar", "lzma", "aff", "gpg", "pgp", "asc", "sig", "key", "pub", "a", "lib", "z", "pic",
}

# Common text extensions. Binary content behind one of these is a mismatch.
TEXT_EXTS = {
    "txt", "text", "csv", "tsv", "md", "markdown", "rst", "json", "jsonl", "xml", "html", "htm",
    "xhtml", "mht", "mhtml", "js", "mjs", "cjs", "ts", "py", "pl", "rb", "php", "sh", "bash",
    "zsh", "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vba", "hta", "wsf", "ini", "cfg",
    "conf", "config", "yaml", "yml", "toml", "c", "h", "cpp", "hpp", "cc", "cs", "java", "go",
    "rs", "swift", "kt", "css", "scss", "sql", "svg", "eml", "ics", "vcf", "url", "reg",
    "inf", "srt", "vtt", "tex", "nfo", "properties", "env", "lua", "r", "m", "asm", "s",
}

BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮",
              "⁦", "⁧", "⁨", "⁩", "‎", "‏"}

# --------------------------------------------------------------------------
# Signature table
#
# (name, category, offset, magic, extensions)   "" in extensions = no extension is fine

SIGNATURES = [
    # executables
    ("ELF executable", "executable", 0, b"\x7fELF", ("", "so", "ko", "elf", "bin", "o", "axf", "prx", "out", "run", "elf32", "elf64")),
    ("Mach-O executable", "executable", 0, b"\xfe\xed\xfa\xce", ("", "dylib", "bundle", "so", "o", "kext", "node")),
    ("Mach-O executable", "executable", 0, b"\xfe\xed\xfa\xcf", ("", "dylib", "bundle", "so", "o", "kext", "node")),
    ("Mach-O executable", "executable", 0, b"\xce\xfa\xed\xfe", ("", "dylib", "bundle", "so", "o", "kext", "node")),
    ("Mach-O executable", "executable", 0, b"\xcf\xfa\xed\xfe", ("", "dylib", "bundle", "so", "o", "kext", "node")),
    ("Android DEX bytecode", "executable", 0, b"dex\n0", ("dex", "odex")),
    ("WebAssembly module", "executable", 0, b"\x00asm", ("wasm",)),
    ("Windows shortcut (LNK)", "shortcut", 0, b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F", ("lnk",)),
    ("Compiled HTML help (CHM)", "help", 0, b"ITSF", ("chm",)),
    ("Windows cabinet (CAB)", "archive", 0, b"MSCF", ("cab", "msu", "onepkg", "xsn", "ppkg", "snp")),
    ("macOS installer / XAR", "installer", 0, b"xar!", ("pkg", "xip", "xar", "mpkg", "safariextz")),
    # documents
    ("PDF document", "document", 0, b"%PDF-", ("pdf", "ai", "fdf")),
    ("PostScript", "document", 0, b"%!PS", ("ps", "eps", "epsf", "ai", "pfa", "t42")),
    ("Encapsulated PostScript (DOS EPS)", "document", 0, b"\xc5\xd0\xd3\xc6", ("eps", "epsf")),
    ("Rich Text Format (RTF)", "document", 0, b"{\\rtf", ("rtf",)),
    ("OneNote document", "document", 0, bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3"), ("one",)),
    ("Apple binary property list", "document", 0, b"bplist0", ("plist", "bplist", "", "webloc", "strings", "nib")),
    ("Apple binary cookies", "database", 0, b"cook", ("binarycookies",)),
    ("macOS keychain", "database", 0, b"kych", ("keychain", "keychain-db")),
    ("macOS .DS_Store", "database", 0, b"\x00\x00\x00\x01Bud1", ("", "ds_store")),
    # images
    ("PNG image", "image", 0, b"\x89PNG\r\n\x1a\n", ("png", "apng")),
    ("JPEG image", "image", 0, b"\xff\xd8\xff", ("jpg", "jpeg", "jpe", "jfif", "jif", "jfi", "thm", "jps", "mpo")),
    ("GIF image", "image", 0, b"GIF87a", ("gif",)),
    ("GIF image", "image", 0, b"GIF89a", ("gif",)),
    ("TIFF image / camera raw", "image", 0, b"II*\x00", ("tif", "tiff", "dng", "nef", "nrw", "cr2", "arw", "sr2", "srf", "orf", "pef", "srw", "3fr", "erf", "kdc", "mos", "iiq", "rwl", "dcr")),
    ("TIFF image / camera raw", "image", 0, b"MM\x00*", ("tif", "tiff", "dng", "nef", "3fr", "mos", "iiq", "pef", "erf")),
    ("Panasonic RW2 raw image", "image", 0, b"IIU\x00", ("rw2", "raw", "rwl")),
    ("Olympus ORF raw image", "image", 0, b"IIRO", ("orf",)),
    ("Fujifilm RAF raw image", "image", 0, b"FUJIFILMCCD-RAW", ("raf",)),
    ("Photoshop image (PSD)", "image", 0, b"8BPS", ("psd", "psb")),
    ("JPEG 2000 image", "image", 0, b"\x00\x00\x00\x0cjP  \r\n\x87\n", ("jp2", "j2k", "jpf", "jpx", "jpm", "mj2")),
    ("JPEG XL image", "image", 0, b"\xff\x0a", ("jxl",)),
    ("JPEG XL image", "image", 0, b"\x00\x00\x00\x0cJXL \r\n\x87\n", ("jxl",)),
    ("Windows icon", "image", 0, b"\x00\x00\x01\x00", ("ico",)),
    ("Windows cursor", "image", 0, b"\x00\x00\x02\x00", ("cur",)),
    ("GIMP image (XCF)", "image", 0, b"gimp xcf", ("xcf",)),
    ("OpenEXR image", "image", 0, b"v/1\x01", ("exr",)),
    ("Radiance HDR image", "image", 0, b"#?RADIANCE", ("hdr", "pic", "rgbe")),
    ("DjVu document", "document", 0, b"AT&TFORM", ("djvu", "djv")),
    # audio / video
    ("FLAC audio", "audio", 0, b"fLaC", ("flac",)),
    ("Ogg media", "audio", 0, b"OggS", ("ogg", "oga", "ogv", "opus", "spx", "ogx", "ogm")),
    ("MIDI audio", "audio", 0, b"MThd", ("mid", "midi", "kar", "rmi")),
    ("MP3 audio (ID3 tag)", "audio", 0, b"ID3", ("mp3", "mp2", "mpga", "aac", "flac", "aif", "aiff", "wav", "m4a")),
    ("Matroska / WebM video", "video", 0, b"\x1a\x45\xdf\xa3", ("mkv", "webm", "mka", "mks", "mk3d", "weba")),
    ("Flash video (FLV)", "video", 0, b"FLV\x01", ("flv", "f4v")),
    ("Windows Media (ASF)", "video", 0, bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c"), ("wmv", "wma", "asf", "dvr-ms")),
    ("MPEG program stream", "video", 0, b"\x00\x00\x01\xba", ("mpg", "mpeg", "vob", "m2p", "mod", "evo")),
    ("MPEG video", "video", 0, b"\x00\x00\x01\xb3", ("mpg", "mpeg", "m1v", "m2v", "mpv")),
    ("RealMedia", "video", 0, b".RMF", ("rm", "rmvb", "ra")),
    ("Shockwave Flash (SWF)", "executable", 0, b"FWS", ("swf",)),
    ("Shockwave Flash (SWF)", "executable", 0, b"CWS", ("swf",)),
    ("Shockwave Flash (SWF)", "executable", 0, b"ZWS", ("swf",)),
    # archives and compression
    ("RAR archive", "archive", 0, b"Rar!\x1a\x07", ("rar", "cbr", "001", "r00", "part1")),
    ("7-Zip archive", "archive", 0, b"7z\xbc\xaf\x27\x1c", ("7z", "cb7", "001")),
    ("gzip compressed", "archive", 0, b"\x1f\x8b", ("gz", "tgz", "gzip", "svgz", "z", "emz", "wmz", "taz", "nii")),
    ("bzip2 compressed", "archive", 0, b"BZh", ("bz2", "tbz", "tbz2", "tb2", "bz")),
    ("xz compressed", "archive", 0, b"\xfd7zXZ\x00", ("xz", "txz")),
    ("Zstandard compressed", "archive", 0, b"\x28\xb5\x2f\xfd", ("zst", "tzst", "zstd")),
    ("LZ4 compressed", "archive", 0, b"\x04\x22\x4d\x18", ("lz4",)),
    ("Unix compress (.Z)", "archive", 0, b"\x1f\x9d", ("z", "taz")),
    ("lzip compressed", "archive", 0, b"LZIP", ("lz", "tlz")),
    ("ARJ archive", "archive", 0, b"\x60\xea", ("arj",)),
    ("Debian package / ar archive", "archive", 0, b"!<arch>\n", ("deb", "a", "ar", "lib", "udeb", "ipk")),
    ("thin ar archive", "archive", 0, b"!<thin>\n", ("a", "lib")),
    ("RPM package", "installer", 0, b"\xed\xab\xee\xdb", ("rpm",)),
    ("Chrome extension (CRX)", "archive", 0, b"Cr24", ("crx",)),
    ("Java module (JMOD)", "archive", 0, b"JM\x01\x00", ("jmod",)),
    ("tar archive", "archive", 257, b"ustar", ("tar", "gem", "ova")),
    # disk images and forensic containers
    ("ISO 9660 disc image", "disk", 0x8001, b"CD001", ("iso", "img", "udf", "cdr", "toast", "bin")),
    ("ISO 9660 disc image", "disk", 0x8801, b"CD001", ("iso", "img", "udf", "cdr", "toast", "bin")),
    ("ISO 9660 disc image", "disk", 0x9001, b"CD001", ("iso", "img", "udf", "cdr", "toast", "bin")),
    ("VHD virtual disk", "disk", 0, b"conectix", ("vhd", "avhd")),
    ("VHDX virtual disk", "disk", 0, b"vhdxfile", ("vhdx", "avhdx")),
    ("VMDK virtual disk", "disk", 0, b"KDMV", ("vmdk",)),
    ("QEMU QCOW disk", "disk", 0, b"QFI\xfb", ("qcow2", "qcow", "img")),
    ("VirtualBox VDI disk", "disk", 0x40, b"\x7f\x10\xda\xbe", ("vdi",)),
    ("EnCase evidence file (E01)", "disk", 0, b"EVF\x09\x0d\x0a\xff\x00", ("e01", "e02", "s01", "ex01")),
    ("EnCase evidence file (Ex01)", "disk", 0, b"EVF2\r\n\x81\x00", ("ex01", "e01")),
    ("EnCase logical evidence (L01)", "disk", 0, b"LVF\x09\x0d\x0a\xff\x00", ("l01", "lx01")),
    ("AFF forensic image", "disk", 0, b"AFF10\r\n", ("aff",)),
    ("Apple sparse disk image", "disk", 0, b"sprs", ("sparseimage",)),
    ("Apple encrypted disk image", "disk", 0, b"encrcdsa", ("dmg", "sparseimage", "sparsebundle")),
    # databases and system artifacts
    ("SQLite database", "database", 0, b"SQLite format 3\x00", ("", "sqlite", "sqlite3", "db", "db3", "s3db", "sqlitedb", "sl3", "localstorage", "storedata", "vdb")),
    ("Windows registry hive", "database", 0, b"regf", ("", "dat", "hve", "hiv", "log1", "log2")),
    ("Windows event log (EVTX)", "log", 0, b"ElfFile\x00", ("evtx",)),
    ("Windows event log (EVT)", "log", 4, b"LfLe", ("evt",)),
    ("Windows prefetch", "log", 4, b"SCCA", ("pf",)),
    ("Windows prefetch (compressed)", "log", 0, b"MAM\x04", ("pf",)),
    ("ESE database", "database", 4, b"\xef\xcd\xab\x89", ("edb", "dat", "sdb", "jfm", "ese", "db", "srudb")),
    ("Windows minidump", "dump", 0, b"MDMP", ("dmp", "mdmp", "hdmp")),
    ("Windows kernel dump", "dump", 0, b"PAGEDU64", ("dmp",)),
    ("Windows kernel dump", "dump", 0, b"PAGEDUMP", ("dmp",)),
    ("Windows hibernation file", "dump", 0, b"hibr", ("sys",)),
    ("Windows hibernation file", "dump", 0, b"HIBR", ("sys",)),
    ("Windows hibernation file", "dump", 0, b"wake", ("sys",)),
    ("Windows hibernation file", "dump", 0, b"RSTR", ("sys",)),
    ("pcap capture", "capture", 0, b"\xd4\xc3\xb2\xa1", ("pcap", "cap", "dmp", "pcapng")),
    ("pcap capture", "capture", 0, b"\xa1\xb2\xc3\xd4", ("pcap", "cap", "dmp", "pcapng")),
    ("pcap capture (ns)", "capture", 0, b"\x4d\x3c\xb2\xa1", ("pcap", "cap", "pcapng")),
    ("pcapng capture", "capture", 0, b"\x0a\x0d\x0d\x0a", ("pcapng", "pcap", "ntar", "cap")),
    ("Java KeyStore", "database", 0, b"\xfe\xed\xfe\xed", ("jks", "keystore", "ks")),
    ("Outlook data file (PST/OST)", "database", 0, b"!BDN", ("pst", "ost", "pab")),
    ("Microsoft Access database", "database", 4, b"Standard Jet DB", ("mdb", "mde", "mdt", "accdb")),
    ("Microsoft Access database", "database", 4, b"Standard ACE DB", ("accdb", "accde", "accdt", "mdb")),
    ("KeePass database", "database", 0, b"\x03\xd9\xa2\x9a", ("kdbx", "kdb")),
    ("Bitcoin Core wallet / Berkeley DB", "database", 12, b"\x62\x31\x05\x00", ("dat", "db", "wallet")),
    ("Torrent file", "document", 0, b"d8:announce", ("torrent",)),
    ("Torrent file", "document", 0, b"d13:announce-list", ("torrent",)),
    # fonts
    ("OpenType font", "font", 0, b"OTTO", ("otf",)),
    ("TrueType collection", "font", 0, b"ttcf", ("ttc", "otc")),
    ("WOFF font", "font", 0, b"wOFF", ("woff",)),
    ("WOFF2 font", "font", 0, b"wOF2", ("woff2",)),
    # keys and certificates
    ("PGP / GPG data", "crypto", 0, b"\x99\x01", ("gpg", "pgp", "pub", "key", "asc", "kbx")),
    ("PGP / GPG data", "crypto", 0, b"\x85\x01", ("gpg", "pgp", "sig")),
    ("LUKS encrypted volume", "disk", 0, b"LUKS\xba\xbe", ("luks", "img", "")),
    ("BitLocker volume", "disk", 3, b"-FVE-FS-", ("", "img", "dd", "raw", "bek", "vhd")),
]

# Signatures whose magic is short enough to match random data now and then.
# They identify a file only when its extension agrees.
WEAK_SIGNATURES = [
    ("MP3 audio", "audio", (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"\xff\xfa", b"\xff\xe3"), ("mp3", "mp2", "mpga")),
    ("AAC audio (ADTS)", "audio", (b"\xff\xf1", b"\xff\xf9"), ("aac", "adts")),
    ("TrueType font", "font", (b"\x00\x01\x00\x00\x00", b"true"), ("ttf", "tte", "dfont")),
    ("Truevision TGA image", "image", (), ("tga", "tpic", "icb", "vda", "vst")),
]

# --------------------------------------------------------------------------
# Reading files without disturbing them

def open_evidence(path):
    """Open read-only, without updating the access time where the OS allows it."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    noatime = getattr(os, "O_NOATIME", 0)
    if noatime:
        try:
            return os.fdopen(os.open(path, flags | noatime), "rb", buffering=0)
        except OSError:
            pass
    return os.fdopen(os.open(path, flags), "rb", buffering=0)


def read_at(f, offset, size):
    f.seek(offset)
    out = bytearray()
    while len(out) < size:
        b = f.read(size - len(out))
        if not b:
            break
        out += b
    return bytes(out)


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024

# --------------------------------------------------------------------------
# Identification

class Ident:
    """What a file's content says it is."""

    def __init__(self, name, category, exts, weak=False):
        self.name = name
        self.category = category
        self.exts = set(exts)
        self.weak = weak
        self.notes = []       # extra facts (shown with the type)
        self.flags = []       # findings (shown with !)
        self.zip_names = None
        self.ole_names = None


def identify_pe(f, head, size):
    ident = Ident("DOS executable (MZ)", "executable", ("exe", "com", "ovl", "drv", "sys"))
    if len(head) < 0x40:
        return ident
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > size - 24:
        return ident
    pe = read_at(f, e_lfanew, 24 + 96)
    if pe[:4] != b"PE\x00\x00":
        if pe[:2] in (b"NE", b"LE", b"LX"):
            ident.name = f"16-bit Windows/OS2 executable ({pe[:2].decode()})"
        return ident
    machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", pe, 4)
    arch = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA64",
            0x1C4: "ARMv7", 0xEBC: "EFI bytecode"}.get(machine, hex(machine))
    subsystem = None
    magic = None
    if opt_size >= 70 and len(pe) >= 24 + 70:
        magic = struct.unpack_from("<H", pe, 24)[0]
        subsystem = struct.unpack_from("<H", pe, 24 + 68)[0]
    is_dll = bool(chars & 0x2000)
    kind = "DLL" if is_dll else "EXE"
    if subsystem == 1:
        kind = "driver"
    elif subsystem in (10, 11, 12, 13):
        kind = "EFI"
    ident.name = f"PE executable ({kind}, {arch})"
    if kind == "DLL":
        ident.exts = {"dll", "ocx", "cpl", "ax", "drv", "mui", "pyd", "node", "winmd",
                      "tlb", "acm", "tsp", "ime", "wll", "xll", "sys", "efi", "scr", "exe", "rll", "lex", "dll_"}
    elif kind == "driver":
        ident.exts = {"sys", "drv", "dll", "efi"}
    elif kind == "EFI":
        ident.exts = {"efi", "sys", "exe", "dll", "bin"}
    else:
        ident.exts = {"exe", "scr", "com", "cpl", "pif", "efi", "sfx", "mui", "dll", "ex_", "bin"}
    if subsystem == 2 and kind == "EXE":
        ident.notes.append("GUI")
    elif subsystem == 3 and kind == "EXE":
        ident.notes.append("console")
    # .NET: CLR runtime header data directory (index 14)
    if magic in (0x10B, 0x20B):
        dd_off = 24 + (96 if magic == 0x10B else 112) + 14 * 8
        clr = read_at(f, e_lfanew + dd_off, 8)
        if len(clr) == 8 and struct.unpack("<II", clr)[0]:
            ident.notes.append(".NET")
    return ident


def identify_ftyp(head):
    brand = head[8:12]
    compat = head[16:64]
    b = brand.decode("latin-1").strip().lower()
    if b in ("heic", "heix", "hevc", "hevx", "heim", "heis") or (b in ("mif1", "msf1") and b"heic" in compat):
        return Ident("HEIC image", "image", ("heic", "heif", "hif", "heics"))
    if b in ("avif", "avis") or (b == "mif1" and b"avif" in compat):
        return Ident("AVIF image", "image", ("avif", "avifs"))
    if b in ("mif1", "msf1"):
        return Ident("HEIF image", "image", ("heif", "heic", "hif", "avif"))
    if b == "crx":
        return Ident("Canon CR3 raw image", "image", ("cr3",))
    if b == "qt":
        return Ident("QuickTime video", "video", ("mov", "qt", "mp4", "m4v"))
    if b.startswith("3g"):
        return Ident("3GPP video", "video", ("3gp", "3g2", "3gpp", "3gp2", "mp4"))
    if b in ("m4a", "m4b", "m4p", "f4a"):
        return Ident(f"MPEG-4 audio ({b.upper()})", "audio", ("m4a", "m4b", "m4p", "mp4", "aac", "f4a", "m4r"))
    if b == "jp2" or b == "jpx":
        return Ident("JPEG 2000 image", "image", ("jp2", "jpf", "jpx"))
    return Ident("MPEG-4 video", "video", ("mp4", "m4v", "m4a", "m4b", "m4p", "mov", "3gp", "f4v", "f4a", "ismv", "isma", "mp4v", "dash", "m4s", "m4r", "lrv"))


def identify_riff(head):
    form = head[8:12]
    table = {
        b"WAVE": ("WAV audio", "audio", ("wav", "wave", "bwf")),
        b"AVI ": ("AVI video", "video", ("avi", "divx")),
        b"WEBP": ("WebP image", "image", ("webp",)),
        b"ACON": ("Windows animated cursor", "image", ("ani",)),
        b"RMID": ("RIFF MIDI audio", "audio", ("mid", "midi", "rmi")),
        b"CDXA": ("Video CD (CDXA)", "video", ("dat", "mpg")),
        b"AMV ": ("AMV video", "video", ("amv",)),
    }
    if form in table:
        return Ident(*table[form])
    return Ident(f"RIFF container ({form.decode('latin-1').strip()})", "other", ("riff", "rif"))


def identify_form(head):
    form = head[8:12]
    if form in (b"AIFF", b"AIFC"):
        return Ident("AIFF audio", "audio", ("aif", "aiff", "aifc", "snd"))
    if form == b"ILBM":
        return Ident("IFF image (ILBM)", "image", ("iff", "ilbm", "lbm"))
    if form == b"8SVX":
        return Ident("IFF audio (8SVX)", "audio", ("8svx", "iff", "svx"))
    return Ident("IFF container", "other", ("iff",))


def identify_bmp(head, size):
    if len(head) < 18:
        return None
    dib = struct.unpack_from("<I", head, 14)[0]
    if dib in (12, 40, 52, 56, 64, 108, 124) and struct.unpack_from("<I", head, 6)[0] == 0:
        return Ident("BMP image", "image", ("bmp", "dib", "rle"))
    return None


def identify_classfile(head):
    # 0xCAFEBABE is both a Java class file and a universal (fat) Mach-O.
    n = struct.unpack_from(">I", head, 4)[0] if len(head) >= 8 else 0
    if 0 < n < 40:
        return Ident("Mach-O universal binary", "executable", ("", "dylib", "bundle", "so", "o", "kext", "node"))
    return Ident("Java class file", "executable", ("class",))


def ole_directory_names(f, head, size):
    """Stream and storage names from an OLE compound file (old Office, MSI, MSG...)."""
    if len(head) < 512:
        return []
    shift = struct.unpack_from("<H", head, 30)[0]
    if shift not in (9, 12):
        return []
    ssz = 1 << shift
    first_dir = struct.unpack_from("<I", head, 48)[0]
    difat = struct.unpack_from("<109I", head, 76)
    per_fat = ssz // 4

    def sector_off(sid):
        return (sid + 1) * ssz

    def next_sector(sid):
        idx = sid // per_fat
        if idx >= 109 or difat[idx] >= 0xFFFFFFFA:
            return 0xFFFFFFFE
        raw = read_at(f, sector_off(difat[idx]) + (sid % per_fat) * 4, 4)
        return struct.unpack("<I", raw)[0] if len(raw) == 4 else 0xFFFFFFFE

    names = []
    sid, seen = first_dir, set()
    while sid < 0xFFFFFFFA and sid not in seen and len(seen) < 128:
        seen.add(sid)
        if sector_off(sid) >= size:
            break
        data = read_at(f, sector_off(sid), ssz)
        for i in range(0, len(data) - 127, 128):
            nlen = struct.unpack_from("<H", data, i + 64)[0]
            if 2 <= nlen <= 64 and data[i + 66] in (1, 2, 5):
                try:
                    names.append(data[i:i + nlen - 2].decode("utf-16-le"))
                except UnicodeDecodeError:
                    pass
        sid = next_sector(sid)
    return names


def identify_ole(f, head, size):
    names = ole_directory_names(f, head, size)
    low = {n.lower() for n in names}
    generic = ("doc", "dot", "xls", "xlt", "xla", "ppt", "pps", "pot", "msi", "msp", "mst", "msm",
               "msg", "vsd", "vss", "vst", "pub", "db", "mpp", "wps", "sldprt", "max", "suo",
               "automaticdestinations-ms", "ole", "ole2", "wiz", "xlw", "shw", "sda", "mdi")
    ident = Ident("OLE compound file", "document", generic)
    if "encryptedpackage" in low:
        ident = Ident("Encrypted Office document", "document",
                      ("docx", "docm", "dotx", "xlsx", "xlsm", "xlsb", "xltx", "pptx", "pptm", "ppsx", "potx", "vsdx",
                       "doc", "xls", "ppt"))
        ident.notes.append("password-protected")
    elif "worddocument" in low:
        ident = Ident("Word 97-2003 document", "document", ("doc", "dot", "wiz"))
    elif "workbook" in low or "book" in low:
        ident = Ident("Excel 97-2003 workbook", "document", ("xls", "xlt", "xla", "xlw", "xlm"))
    elif "powerpoint document" in low:
        ident = Ident("PowerPoint 97-2003 presentation", "document", ("ppt", "pps", "pot", "ppa"))
    elif "visiodocument" in low:
        ident = Ident("Visio 2003 drawing", "document", ("vsd", "vss", "vst", "vdx"))
    elif "contents" in low and "quill" in low:
        ident = Ident("Publisher document", "document", ("pub",))
    elif any(n.startswith("__substg1.0_") or n.startswith("__nameid_version1.0") for n in low):
        ident = Ident("Outlook message (MSG)", "document", ("msg", "oft"))
    elif any(ord(c) >= 0x3800 for n in names for c in n[:1]) and any(n.endswith("SummaryInformation") for n in names):
        ident = Ident("Windows Installer package", "installer", ("msi", "msp", "mst", "msm", "pcp", "idt"))
    elif "destlist" in low:
        ident = Ident("Windows jump list", "log", ("automaticdestinations-ms",))
    elif "catalog" in low and any(n.isdigit() for n in names):
        ident = Ident("Windows thumbnail cache (Thumbs.db)", "database", ("db",))
    ident.ole_names = names
    if "macros" in low or "_vba_project_cur" in low or "vba" in low or "_vba_project" in low:
        ident.flags.append("contains VBA macros")
    if any(n.lower() in ("\x01ole10native", "ole10native") for n in names):
        ident.flags.append("contains an embedded OLE package (Ole10Native)")
    return ident


OOXML_KINDS = (
    ("word/", "Word document (OOXML)", ("docx", "docm", "dotx", "dotm")),
    ("xl/", "Excel workbook (OOXML)", ("xlsx", "xlsm", "xltx", "xltm", "xlsb", "xlam")),
    ("ppt/", "PowerPoint presentation (OOXML)", ("pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "ppam", "sldx")),
    ("visio/", "Visio drawing (OOXML)", ("vsdx", "vsdm", "vssx", "vstx")),
)

ODF_MIMES = {
    "application/vnd.oasis.opendocument.text": ("OpenDocument text", ("odt", "ott")),
    "application/vnd.oasis.opendocument.spreadsheet": ("OpenDocument spreadsheet", ("ods", "ots")),
    "application/vnd.oasis.opendocument.presentation": ("OpenDocument presentation", ("odp", "otp")),
    "application/vnd.oasis.opendocument.graphics": ("OpenDocument drawing", ("odg", "otg")),
    "application/epub+zip": ("EPUB e-book", ("epub",)),
    "application/vnd.adobe.indesign-idml-package": ("InDesign IDML", ("idml",)),
    "image/openraster": ("OpenRaster image", ("ora",)),
    "application/x-krita": ("Krita image", ("kra",)),
}

GENERIC_ZIP_EXTS = (
    "zip", "zipx", "cbz", "xpi", "whl", "egg", "nupkg", "vsix", "ipa", "kmz", "sketch", "apkg",
    "oxt", "gadget", "3mf", "usdz", "pk3", "pk4", "mcpack", "mcworld", "mcaddon", "xapk",
    "aar", "jar", "war", "ear", "xap", "appxbundle", "msixbundle", "001", "sb3", "twbx",
    "pbix", "pbit", "fig", "fla", "key", "numbers", "pages", "gz", "wmz", "zip_",
    "mpkg", "cbt", "dwfx", "xps", "oxps", "ova", "bundle", "lpk", "pbiviz", "crx", "air",
)


def identify_zip(f, size, max_scan):
    ident = Ident("ZIP archive", "archive", GENERIC_ZIP_EXTS)
    try:
        f.seek(0)
        zf = zipfile.ZipFile(f)
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError, struct.error):
        ident.notes.append("damaged or incomplete")
        return ident
    names = [i.filename for i in infos]
    ident.zip_names = names
    low = [n.lower() for n in names]
    lowset = set(low)

    def read_member(name, limit=200):
        try:
            with zf.open(name) as m:
                return m.read(limit)
        except Exception:
            return b""

    if "mimetype" in lowset:
        mime = read_member(names[low.index("mimetype")]).decode("ascii", "ignore").strip()
        if mime in ODF_MIMES:
            label, exts = ODF_MIMES[mime]
            ident = Ident(label, "document", exts)
        elif mime.startswith("application/vnd.oasis.opendocument"):
            ident = Ident("OpenDocument file", "document", ("odt", "ods", "odp", "odg", "odf", "odb", "odc", "odm", "otg", "otp", "ots", "ott"))
    elif "[content_types].xml" in lowset:
        for prefix, label, exts in OOXML_KINDS:
            if any(n.startswith(prefix) for n in low):
                ident = Ident(label, "document", exts)
                break
        else:
            if any(n.endswith(".nuspec") for n in low):
                ident = Ident("NuGet package", "archive", ("nupkg", "snupkg"))
            elif "extension.vsixmanifest" in lowset:
                ident = Ident("Visual Studio extension (VSIX)", "archive", ("vsix",))
            elif any(n.startswith("documents/") or n == "fixeddocumentsequence.fdseq" for n in low):
                ident = Ident("XPS document", "document", ("xps", "oxps"))
            elif "appxmanifest.xml" in lowset or "appxmetadata/appxbundlemanifest.xml" in lowset:
                ident = Ident("Windows app package (MSIX/APPX)", "installer", ("msix", "appx", "msixbundle", "appxbundle"))
            else:
                ident = Ident("Office Open XML package", "document",
                              tuple(e for _, _, es in OOXML_KINDS for e in es) + ("3mf", "dwfx"))
    elif "androidmanifest.xml" in lowset:
        ident = Ident("Android app (APK)", "installer", ("apk", "apks", "xapk", "jar", "zip"))
    elif "base/manifest/androidmanifest.xml" in lowset:
        ident = Ident("Android app bundle (AAB)", "installer", ("aab",))
    elif any(n.startswith("payload/") and ".app/" in n for n in low):
        ident = Ident("iOS app (IPA)", "installer", ("ipa",))
    elif "meta-inf/manifest.mf" in lowset or any(n.endswith(".class") for n in low):
        ident = Ident("Java archive (JAR)", "executable", ("jar", "war", "ear", "jmod", "zip", "apk", "aar", "jnlp"))
    elif "doc.kml" in lowset:
        ident = Ident("Google Earth KMZ", "document", ("kmz",))
    elif any(".dist-info/" in n for n in low):
        ident = Ident("Python wheel", "archive", ("whl", "zip"))
    elif "manifest.json" in lowset and any(n.endswith(".js") for n in low):
        ident = Ident("Browser extension", "archive", ("xpi", "zip", "crx"))
    ident.zip_names = names

    # Macros, executables, encryption
    if any(n.endswith("vbaproject.bin") for n in low):
        ident.flags.append("contains VBA macros (vbaProject.bin)")
    if any(i.flag_bits & 0x1 for i in infos):
        ident.flags.append("password-protected entries")
    risky = [n for n in names if not n.endswith("/") and ext_of(os.path.basename(n)) in RISKY_EXT]
    if risky and ident.category == "archive" and (len(names) <= 10 or ident.name == "ZIP archive" and len(risky) == len(names)):
        shown = ", ".join(os.path.basename(n) for n in risky[:3]) + (" ..." if len(risky) > 3 else "")
        ident.flags.append(f"small archive holding executable/script files: {shown}")
    ident.notes.append(f"{len(names)} entr{'y' if len(names) == 1 else 'ies'}")
    return ident


def identify_text(head):
    """Text files have no magic number; label the common kinds."""
    if not head:
        return None
    enc = None
    body = head
    if head.startswith(b"\xef\xbb\xbf"):
        enc, body = "UTF-8 BOM", head[3:]
    elif head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        enc = "UTF-16"
        try:
            body = head[2:len(head) - (len(head) % 2)].decode("utf-16-le" if head[0] == 0xFF else "utf-16-be").encode("utf-8", "ignore")
        except UnicodeDecodeError:
            return None
    else:
        if b"\x00" in head:
            return None
        sample = head[:-4] if len(head) > 8 else head
        try:
            sample.decode("utf-8")
            enc = "UTF-8" if any(b >= 0x80 for b in sample) else "ASCII"
        except UnicodeDecodeError:
            printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13, 12))
            if printable / max(1, len(sample)) < 0.9:
                return None
            enc = "8-bit"
        ctrl = sum(1 for b in sample if b < 32 and b not in (9, 10, 13, 12, 27))
        if ctrl / max(1, len(sample)) > 0.01:
            return None

    s = body.lstrip()[:2048]
    sl = s.lower()
    if s.startswith(b"#!"):
        interp = s[2:].split(b"\n", 1)[0].strip().decode("latin-1")[:40]
        ident = Ident(f"script ({interp})" if interp else "script", "script",
                      ("", "sh", "bash", "zsh", "ksh", "csh", "py", "pl", "rb", "php", "js", "mjs", "command",
                       "tool", "awk", "tcl", "lua", "cgi", "run", "bin", "fish", "r", "swift", "txt", "in"))
    elif sl.startswith(b"/* gnu ld script") or sl.startswith(b"input(") or sl.startswith(b"group ("):
        ident = Ident("linker script", "text", ())
        ident.exts = {"so"}
    elif sl.startswith(b"<?xml") or sl.startswith(b"<svg"):
        if b"<svg" in sl:
            ident = Ident("SVG image (XML)", "image", ("svg",))
        elif b"<!doctype plist" in sl or b"<plist" in sl:
            ident = Ident("Apple property list (XML)", "document", ("plist",))
        else:
            ident = Ident("XML", "text", ())
    elif sl.startswith(b"<!doctype html") or sl.startswith(b"<html") or (sl.startswith(b"<") and b"<html" in sl[:512]):
        ident = Ident("HTML", "text", ())
    elif sl.startswith(b"mime-version:") or (b"content-type: multipart/related" in sl):
        ident = Ident("MIME / MHTML", "text", ())
    elif s.startswith(b"-----BEGIN"):
        ident = Ident("PEM key or certificate", "crypto", ())
    else:
        ident = Ident("text", "text", ())
    ident.notes.append(enc)
    return ident


def identify(f, head, size, max_scan):
    """Return an Ident for the content, or None if nothing matches."""
    if head[:2] == b"MZ":
        return identify_pe(f, head, size)
    if head[:4] == b"\xca\xfe\xba\xbe":
        return identify_classfile(head)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return identify_ole(f, head, size)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        if head[:4] == b"PK\x05\x06":
            return Ident("ZIP archive (empty)", "archive", GENERIC_ZIP_EXTS)
        return identify_zip(f, size, max_scan)
    if head[4:8] == b"ftyp":
        return identify_ftyp(head)
    if head[:4] == b"RIFF" and len(head) >= 12:
        return identify_riff(head)
    if head[:4] == b"FORM" and len(head) >= 12:
        return identify_form(head)
    if head[:2] == b"BM":
        b = identify_bmp(head, size)
        if b:
            return b
    if head[:9] == b"# Disk De":
        return Ident("VMDK descriptor", "disk", ("vmdk",))
    for name, cat, off, magic, exts in SIGNATURES:
        if head[off:off + len(magic)] == magic:
            ident = Ident(name, cat, exts)
            if name == "Matroska / WebM video" and b"webm" in head[:64]:
                ident.name = "WebM video"
            if name == "ELF executable" and len(head) >= 18:
                et = struct.unpack_from("<H" if head[5] == 1 else ">H", head, 16)[0]
                ident.notes.append({1: "relocatable", 2: "executable", 3: "shared object or PIE", 4: "core dump"}.get(et, f"type {et}"))
                if et == 4:
                    ident.category, ident.exts = "dump", {"", "core", "dump", "dmp"}
            return ident
    # MPEG transport stream: sync byte every 188 bytes
    if len(head) >= 188 * 3 and head[0] == head[188] == head[376] == 0x47:
        return Ident("MPEG transport stream", "video", ("ts", "m2ts", "mts", "tsv", "tsa", "m2t", "trp"))
    if len(head) >= 192 * 3 and head[4] == head[196] == head[388] == 0x47:
        return Ident("MPEG transport stream (M2TS)", "video", ("m2ts", "mts", "ts", "m2t"))
    text = identify_text(head)
    if text:
        return text
    return None


def weak_match(head, ext):
    """Short signatures, trusted only when the extension already agrees."""
    for name, cat, magics, exts in WEAK_SIGNATURES:
        if ext in exts and (not magics or any(head.startswith(m) for m in magics)):
            return Ident(name, cat, exts, weak=True)
    return None

# --------------------------------------------------------------------------
# Data hidden after the end of a file

def end_of_png(f, size):
    pos = 8
    while pos + 12 <= size:
        hdr = read_at(f, pos, 8)
        if len(hdr) < 8:
            return None
        length, ctype = struct.unpack(">I4s", hdr)
        pos += 12 + length
        if ctype == b"IEND":
            return pos
        if length > size:
            return None
    return None


def end_of_jpeg(f, size, max_scan):
    """Walk JPEG segments and scan data, returning the offset just after EOI."""
    if size > max_scan:
        return None
    f.seek(0)
    data = f.read(size)
    pos = 2
    n = len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            return None
        marker = data[pos + 1]
        if marker == 0xFF:
            pos += 1
            continue
        if marker == 0xD9:
            return pos + 2
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack_from(">H", data, pos + 2)[0]
        pos += 2 + seglen
        if marker == 0xDA:  # start of scan: entropy-coded data until the next real marker
            while pos + 1 < n:
                i = data.find(b"\xff", pos)
                if i < 0 or i + 1 >= n:
                    return None
                nb = data[i + 1]
                if nb == 0x00 or 0xD0 <= nb <= 0xD7 or nb == 0xFF:
                    pos = i + (1 if nb == 0xFF else 2)
                    continue
                pos = i
                break
    return None


def end_of_gif(f, size, max_scan):
    if size > max_scan:
        return None
    f.seek(0)
    d = f.read(size)
    if len(d) < 13:
        return None
    pos = 13
    flags = d[10]
    if flags & 0x80:
        pos += 3 * (2 << (flags & 7))

    def skip_subblocks(p):
        while p < len(d):
            ln = d[p]
            p += 1
            if ln == 0:
                return p
            p += ln
        return None

    while pos < len(d):
        b = d[pos]
        if b == 0x3B:
            return pos + 1
        if b == 0x21:
            pos = skip_subblocks(pos + 2)
        elif b == 0x2C:
            if pos + 10 > len(d):
                return None
            lf = d[pos + 9]
            pos += 10
            if lf & 0x80:
                pos += 3 * (2 << (lf & 7))
            pos = skip_subblocks(pos + 1)
        else:
            return None
        if pos is None:
            return None
    return None


PDF_TOKENS = re.compile(rb"/(JavaScript|JS|Launch|EmbeddedFile|OpenAction|AA|RichMedia|XFA|URI|SubmitForm)(?=[\s/<>\[\]()%]|$)")


def scan_pdf(f, size, max_scan):
    """Find the last %%EOF and count risky PDF keywords. Returns (end, Counter)."""
    counts = Counter()
    last_eof = None
    limit = min(size, max_scan)
    keep = 24                     # bytes carried over so tokens split across chunks are seen
    f.seek(0)
    pos = 0                       # file offset of the start of buf
    buf = b""
    read = 0
    while read < limit:
        chunk = f.read(min(CHUNK, limit - read))
        if not chunk:
            break
        read += len(chunk)
        buf += chunk
        final = read >= limit
        cut = len(buf) if final else max(0, len(buf) - keep)
        for m in PDF_TOKENS.finditer(buf):
            if m.start() < cut:
                counts[m.group(1).decode()] += 1
        i = buf.rfind(b"%%EOF")
        if i >= 0:
            last_eof = pos + i + 5
        if not final:
            pos += cut
            buf = buf[cut:]
    if size > max_scan:
        tail = read_at(f, max(0, size - 4096), 4096)
        i = tail.rfind(b"%%EOF")
        last_eof = max(0, size - 4096) + i + 5 if i >= 0 else None
    return last_eof, counts


def end_of_zip(f, size):
    tail_len = min(size, 65557)
    tail = read_at(f, size - tail_len, tail_len)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or i + 22 > len(tail):
        return None
    clen = struct.unpack_from("<H", tail, i + 20)[0]
    return size - tail_len + i + 22 + clen


def describe_payload(f, offset, size, max_scan):
    head = read_at(f, offset, 64)
    if not head.strip(b"\x00\r\n\t "):
        return None
    if head[:2] == b"MZ":
        return "PE/DOS executable"
    for name, cat, off, magic, exts in SIGNATURES:
        if off == 0 and head.startswith(magic):
            return name
    if head[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "OLE compound file"
    return "unrecognized data"


def trailing_data(f, ident, size, max_scan):
    name = ident.name
    end = None
    label = None
    if name == "PNG image":
        end, label = end_of_png(f, size), "PNG"
    elif name == "JPEG image":
        end, label = end_of_jpeg(f, size, max_scan), "JPEG"
    elif name == "GIF image":
        end, label = end_of_gif(f, size, max_scan), "GIF"
    elif ident.zip_names is not None or name.startswith("ZIP"):
        end, label = end_of_zip(f, size), "ZIP"
    if end is None or end >= size:
        return
    extra = size - end
    rest = read_at(f, end, min(extra, 4096))
    if not rest.strip(b"\x00\r\n\t \xff"):
        return  # padding
    what = describe_payload(f, end, size, max_scan)
    msg = f"{human(extra)} of data after the end of the {label}"
    if what and what != "unrecognized data":
        msg += f" (starts like: {what})"
    ident.flags.append(msg)


def check_pdf(f, ident, size, max_scan):
    end, counts = scan_pdf(f, size, max_scan)
    if end is not None and end < size:
        rest = read_at(f, end, min(size - end, 4096))
        if rest.strip(b"\x00\r\n\t "):
            what = describe_payload(f, end + (len(rest) - len(rest.lstrip(b'\x00\r\n\t '))), size, max_scan)
            msg = f"{human(size - end)} of data after the last %%EOF"
            if what and what != "unrecognized data":
                msg += f" (starts like: {what})"
            ident.flags.append(msg)
    active = [k for k in ("JavaScript", "JS", "Launch", "EmbeddedFile", "RichMedia", "XFA", "SubmitForm") if counts.get(k)]
    if active:
        parts = [f"/{k} x{counts[k]}" for k in active]
        for k in ("OpenAction", "AA"):
            if counts.get(k):
                parts.append(f"/{k} x{counts[k]}")
        ident.flags.append("PDF has active content: " + ", ".join(parts))
    if size > max_scan:
        ident.notes.append(f"only first {human(max_scan)} scanned")

# --------------------------------------------------------------------------
# Name checks

def ext_of(name):
    base = name.rstrip(" .")
    if base.startswith(".") and base.count(".") == 1:
        return ""
    if re.search(r"\.so(\.\d+)+$", base, re.I):
        return "so"
    _, ext = os.path.splitext(base)
    ext = ext[1:].lower()
    if not ext or ext[0].isdigit() and not ext.isdigit() or "-" in ext or " " in ext:
        return ""   # version suffix (vmlinuz-6.8.0-47-generic, libfoo.so.1.2) or not an extension
    return ext


def name_flags(name):
    flags = []
    if any(c in BIDI_CHARS for c in name):
        shown = name
        if "‮" in name:
            pre, _, post = name.partition("‮")
            shown = pre + post[::-1]
        clean = "".join(c for c in shown if c not in BIDI_CHARS)
        flags.append(f"name contains a right-to-left override; it displays as \"{clean}\"")
    if name != name.rstrip(" .") and name not in (".", ".."):
        flags.append("name ends with a space or dot (hidden on Windows)")
    base = name.rstrip(" .")
    parts = base.lower().split(".")
    if len(parts) >= 3:
        inner, outer = parts[-2].strip(), parts[-1]
        if inner in DECOY_EXT and outer in RISKY_EXT:
            flags.append(f"double extension (.{inner}.{outer})")
    if re.search(r"\s{5,}\.\w+$", base):
        flags.append("long run of spaces before the extension")
    return flags

# --------------------------------------------------------------------------
# Checking one file

BINARY_EXTS = set()
WEAK_EXTS = set()


def build_ext_tables():
    for _, cat, _, _, exts in SIGNATURES:
        BINARY_EXTS.update(exts)
    for exts in (GENERIC_ZIP_EXTS,):
        BINARY_EXTS.update(exts)
    for _, _, exts in OOXML_KINDS:
        BINARY_EXTS.update(exts)
    for _, exts in ODF_MIMES.values():
        BINARY_EXTS.update(exts)
    BINARY_EXTS.update(("exe", "dll", "doc", "xls", "ppt", "msi", "msg", "jar", "class", "apk",
                        "webp", "wav", "avi", "mp4", "mov", "m4a", "heic", "avif", "bmp", "aiff", "aif"))
    for _, _, _, exts in WEAK_SIGNATURES:
        WEAK_EXTS.update(exts)
    # Text-based formats and anything too generic to judge.
    BINARY_EXTS.difference_update(AMBIGUOUS_EXT)
    BINARY_EXTS.difference_update(("ps", "eps", "epsf", "ai", "rtf", "svg", "plist", "webloc", "strings",
                                   "torrent", "asc", "pub", "key", "fdf", "hdr", "pic", "vmdk", "in", "r"))


def safe_name(text):
    """Show hidden direction-changing characters instead of letting them reorder the line."""
    return "".join(f"<U+{ord(c):04X}>" if c in BIDI_CHARS else c for c in text)


def check_file(path, display, args):
    rec = {"path": safe_name(display), "size": None, "ext": "", "type": "", "category": "",
           "status": "", "expected": "", "flags": [], "sha256": ""}
    name = os.path.basename(path)
    ext = ext_of(name)
    rec["ext"] = ext
    rec["flags"].extend(name_flags(name))
    try:
        st = os.stat(path, follow_symlinks=False)
        rec["size"] = st.st_size
        with open_evidence(path) as f:
            size = st.st_size
            if size == 0:
                rec.update(status="empty", type="empty file", category="empty")
                return rec
            head = read_at(f, 0, HEAD_SIZE)
            ident = identify(f, head, size, args.max_scan)
            if ident is None:
                ident = weak_match(head, ext)
            if ident is not None:
                if ident.name == "PDF document" or (head[:1024].find(b"%PDF-") >= 0 and ident.category == "text"):
                    if ident.name != "PDF document":
                        ident = Ident("PDF document", "document", ("pdf", "ai", "fdf"))
                        ident.notes.append("header not at offset 0")
                    check_pdf(f, ident, size, args.max_scan)
                elif not ident.weak:
                    trailing_data(f, ident, size, args.max_scan)
            if args.hash:
                h = hashlib.sha256()
                f.seek(0)
                for chunk in iter(lambda: f.read(CHUNK), b""):
                    h.update(chunk)
                rec["sha256"] = h.hexdigest()
    except PermissionError as e:
        rec.update(status="error", type=f"can't read: {e.strerror}")
        return rec
    except OSError as e:
        rec.update(status="error", type=f"can't read: {e.strerror or e}")
        return rec

    if ident is None:
        sample = head[:8192]
        ent = entropy(sample)
        rec["type"] = "unknown binary data"
        rec["category"] = "unknown"
        if not sample.strip(b"\x00"):
            rec["type"] = "zero-filled data"
            rec["flags"].append("first bytes are all zeros (wiped, sparse or carved?)")
        elif ent > 7.95 and len(sample) >= 4096:
            rec["type"] = "unknown high-entropy data"
            rec["flags"].append(f"high entropy ({ent:.2f} bits/byte): encrypted or compressed")
        elif ent > 7.5 and len(sample) >= 1024:
            rec["type"] = "unknown high-entropy data"
        if ext in BINARY_EXTS and ext not in WEAK_EXTS:
            rec["status"] = "mismatch"
            rec["expected"] = expected_for(ext)
            rec["flags"].insert(0, f"no {rec['expected']} signature: content doesn't match .{ext}")
        else:
            rec["status"] = "unknown"
        return rec

    label = ident.name
    if ident.notes:
        label += " [" + ", ".join(n for n in ident.notes if n) + "]"
    rec["type"] = label
    rec["category"] = ident.category
    rec["flags"].extend(ident.flags)

    if ident.category == "text" or (ident.category == "crypto" and not ident.exts):
        # Text has no fixed extension; only a binary extension is a lie.
        if ext in BINARY_EXTS and ext not in WEAK_EXTS and ext not in ident.exts:
            rec["status"] = "mismatch"
            rec["expected"] = expected_for(ext)
            rec["flags"].insert(0, f"{ident.name.lower() if ident.name != 'HTML' else 'HTML'} content, not {rec['expected']}")
        else:
            rec["status"] = "match"
        return rec

    if ext in ident.exts:
        rec["status"] = "match"
    elif ext == "" and ident.category in ("script",):
        rec["status"] = "match"
    elif ident.category in ("script", "crypto") and ext not in BINARY_EXTS:
        rec["status"] = "match"
    elif ident.name.startswith("SVG") and ext in ("svg", "xml", "svgz", "html", "htm"):
        rec["status"] = "match"
    elif ext in AMBIGUOUS_EXT and ext != "":
        rec["status"] = "match"
    elif ext and ext not in BINARY_EXTS and ext not in TEXT_EXTS and ident.category not in EXEC_CATS:
        # An extension sigcheck doesn't know (app-specific, cache, test data). Nothing to compare.
        rec["status"] = "match"
    elif ext and ext not in BINARY_EXTS and ext not in TEXT_EXTS and ident.name.startswith("ELF"):
        # ELF files carry all sorts of names on Linux (.debug, test binaries); not a lie in itself.
        rec["status"] = "match"
    else:
        rec["status"] = "mismatch"
        rec["expected"] = ", ".join("." + e for e in sorted(ident.exts) if e)[:80]
        if ext == "":
            rec["flags"].insert(0, f"no extension; content is {ident.name}")
        else:
            rec["flags"].insert(0, f"content is {ident.name}, not .{ext}")
        if ident.category in EXEC_CATS and ext != "":
            rec["flags"].insert(1, f"executable content behind a .{ext} extension")
        elif ident.category in EXEC_CATS:
            rec["flags"].insert(1, "executable content with no extension")
    return rec


def expected_for(ext):
    names = sorted({n for n, _, _, _, exts in SIGNATURES if ext in exts})
    if not names:
        for prefix, label, exts in OOXML_KINDS:
            if ext in exts:
                return label
        for label, exts in ODF_MIMES.values():
            if ext in exts:
                return label
        special = {"exe": "PE executable", "dll": "PE executable", "doc": "Word document", "xls": "Excel workbook",
                   "ppt": "PowerPoint presentation", "msi": "Windows Installer", "msg": "Outlook message",
                   "jar": "Java archive", "class": "Java class file", "apk": "Android app",
                   "webp": "WebP image", "wav": "WAV audio", "avi": "AVI video", "mp4": "MPEG-4 video",
                   "mov": "QuickTime video", "m4a": "MPEG-4 audio", "heic": "HEIC image", "avif": "AVIF image",
                   "bmp": "BMP image", "aiff": "AIFF audio", "aif": "AIFF audio", "zip": "ZIP archive"}
        return special.get(ext, f".{ext}")
    return names[0] if len(names) == 1 else " / ".join(names[:2])

# --------------------------------------------------------------------------
# Walking

def iter_targets(targets, args):
    for target in targets:
        if os.path.isdir(target):
            root = target
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if not excluded(os.path.join(dirpath, d), d, args))
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    if excluded(full, fn, args):
                        continue
                    yield full, os.path.relpath(full, root).replace(os.sep, "/")
                if args.no_recurse:
                    break
        else:
            yield target, target


def excluded(full, name, args):
    for pat in args.exclude:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(full.replace(os.sep, "/"), pat):
            return True
    return False


def scan(targets, args):
    for full, display in iter_targets(targets, args):
        try:
            st = os.stat(full, follow_symlinks=False)
        except OSError as e:
            yield {"path": safe_name(display), "size": None, "ext": ext_of(os.path.basename(full)), "type": f"can't read: {e.strerror}",
                   "category": "", "status": "error", "expected": "", "flags": [], "sha256": ""}
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            continue  # devices, pipes, sockets: reading them can block or change state
        yield check_file(full, display, args)

# --------------------------------------------------------------------------
# Output

STATUS_LABEL = {"match": "OK", "mismatch": "MISMATCH", "unknown": "UNKNOWN", "empty": "EMPTY", "error": "ERROR"}


def shown(rec, args):
    if args.status and rec["status"] not in args.status:
        return False
    if args.flagged and not rec["flags"]:
        return False
    if args.all or args.status or args.flagged:
        return True
    return rec["status"] in ("mismatch", "error") or bool(rec["flags"])


def write_table(rows, out, args, totals):
    if rows:
        tw = min(42, max(len("TYPE"), *(len(r["type"]) for r in rows)))
        ew = max(4, *(len(r["ext"]) + 1 for r in rows))
        out.write(f"{'STATUS':<9} {'TYPE':<{tw}}  {'EXT':<{ew}}  PATH\n")
        pad = " " * (9 + 1 + tw + 2 + ew + 2)
        for r in rows:
            t = r["type"] if len(r["type"]) <= tw else r["type"][:tw - 3] + "..."
            mark = "!" if r["flags"] else " "
            ext = "." + r["ext"] if r["ext"] else "-"
            out.write(f"{STATUS_LABEL.get(r['status'], r['status']):<9} {t:<{tw}}  {ext:<{ew}} {mark}{r['path']}\n")
            if args.hash and r["sha256"]:
                out.write(f"{pad}  sha256 {r['sha256']}\n")
            for fl in r["flags"]:
                out.write(f"{pad}! {fl}\n")
        out.write("\n")
    write_summary(out, totals, args, compact=bool(rows))


def write_summary(out, totals, args, compact=False):
    st = totals["status"]
    out.write(f"Checked {totals['files']:,} file{'s' if totals['files'] != 1 else ''} ({human(totals['bytes'])}): "
              f"{st['match']:,} match, {st['mismatch']:,} mismatch, {st['unknown']:,} unknown, "
              f"{st['empty']:,} empty" + (f", {st['error']:,} unreadable" if st["error"] else "")
              + f". {totals['flagged']:,} flagged.\n")
    if not compact and args.summary:
        return
    if args.summary:
        out.write("\nCONTENT TYPES\n")
        for t, n in totals["types"].most_common(25):
            out.write(f"  {n:>7,}  {t}\n")
        if totals["mismatch_pairs"]:
            out.write("\nMISMATCHES (extension -> content)\n")
            for (e, t), n in totals["mismatch_pairs"].most_common(25):
                out.write(f"  {n:>7,}  .{e or '(none)'} -> {t}\n")


def write_csv(rows, out, args):
    w = csv.writer(out)
    cols = ["status", "path", "ext", "type", "category", "expected", "size", "flags"] + (["sha256"] if args.hash else [])
    w.writerow(cols)
    for r in rows:
        w.writerow([r["status"], r["path"], r["ext"], r["type"], r["category"], r["expected"],
                    r["size"] if r["size"] is not None else "", " | ".join(r["flags"])] + ([r["sha256"]] if args.hash else []))


def write_json(rows, out, args, totals):
    doc = {
        "tool": "sigcheck", "version": __version__,
        "summary": {"files": totals["files"], "bytes": totals["bytes"], "flagged": totals["flagged"],
                    **{k: totals["status"][k] for k in ("match", "mismatch", "unknown", "empty", "error")}},
        "files": [{k: v for k, v in r.items() if k != "sha256" or args.hash} for r in rows],
    }
    json.dump(doc, out, indent=2, ensure_ascii=False)
    out.write("\n")


def list_types(out):
    seen = {}
    for name, cat, off, magic, exts in SIGNATURES:
        key = name
        if key in seen:
            seen[key][1].update(exts)
            continue
        seen[key] = [cat, set(exts)]
    extra = [
        ("PE executable (EXE/DLL/driver)", "executable", {"exe", "dll", "sys", "scr", "cpl", "ocx", "efi"}),
        ("Java class / Mach-O universal", "executable", {"class", ""}),
        ("OLE: Office 97-2003, MSI, MSG, jump lists...", "document", {"doc", "xls", "ppt", "msi", "msg"}),
        ("Encrypted Office document", "document", {"docx", "xlsx", "pptx"}),
        ("ZIP family: OOXML, ODF, EPUB, JAR, APK, IPA, MSIX...", "archive", {"zip", "docx", "xlsx", "pptx", "odt", "epub", "jar", "apk"}),
        ("MPEG-4 family: MP4, MOV, M4A, HEIC, AVIF, CR3", "video", {"mp4", "mov", "m4a", "3gp", "heic", "avif", "cr3"}),
        ("RIFF: WAV, AVI, WebP, ANI", "audio", {"wav", "avi", "webp", "ani"}),
        ("AIFF / IFF", "audio", {"aif", "aiff", "iff"}),
        ("BMP image", "image", {"bmp", "dib"}),
        ("MPEG transport stream", "video", {"ts", "m2ts", "mts"}),
        ("Text: scripts (#!), HTML, XML, SVG, plist, PEM", "text", set()),
        ("MP3, AAC, TrueType, TGA (only with matching ext)", "weak", {"mp3", "aac", "ttf", "tga"}),
    ]
    rows = [(n, c, e) for n, (c, e) in seen.items()] + extra
    rows.sort(key=lambda r: (r[1], r[0]))
    out.write(f"{'CATEGORY':<11} {'TYPE':<46} EXTENSIONS\n")
    for n, c, e in rows:
        exts = ", ".join("." + x for x in sorted(e) if x)
        if "" in e:
            exts = (exts + ", " if exts else "") + "(none)"
        out.write(f"{c:<11} {n:<46} {exts}\n")
    out.write(f"\n{len(rows)} types.\n")

# --------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="sigcheck",
        description="Find files whose extension doesn't match their content, plus hidden "
                    "appended data, macros, active PDF content and disguised executables.")
    p.add_argument("targets", nargs="*", metavar="target", help="files or folders to check")
    p.add_argument("-a", "--all", action="store_true", help="show every file, not just problems")
    p.add_argument("--status", action="append", choices=("match", "mismatch", "unknown", "empty", "error"),
                   help="only files with this status (repeatable)")
    p.add_argument("--flagged", action="store_true", help="only files with findings (!)")
    p.add_argument("-x", "--exclude", metavar="GLOB", action="append", default=[],
                   help="skip files and folders matching GLOB (repeatable)")
    p.add_argument("-n", "--no-recurse", action="store_true", help="don't descend into subfolders")
    p.add_argument("--hash", action="store_true", help="add the SHA-256 of each file")
    p.add_argument("--max-scan", metavar="MB", type=float, default=DEFAULT_MAX_SCAN / (1024 * 1024),
                   help="largest file to scan in full for trailing data and PDF keywords (default 256)")
    p.add_argument("--summary", action="store_true", help="table format: add content-type and mismatch counts")
    p.add_argument("--types", action="store_true", help="list the file types sigcheck recognizes")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p, p.parse_args(argv)


def main(argv=None):
    parser, args = parse_args(argv)
    if args.types:
        list_types(sys.stdout)
        return 0
    if not args.targets:
        parser.print_usage(sys.stderr)
        print("sigcheck: error: give at least one file or folder", file=sys.stderr)
        return 2
    missing = [t for t in args.targets if not os.path.lexists(t)]
    if missing:
        for t in missing:
            print(f"sigcheck: no such file or folder: {t}", file=sys.stderr)
        return 2
    args.max_scan = int(args.max_scan * 1024 * 1024)
    build_ext_tables()

    totals = {"files": 0, "bytes": 0, "flagged": 0, "status": Counter(), "types": Counter(), "mismatch_pairs": Counter()}
    rows = []
    for rec in scan(args.targets, args):
        totals["files"] += 1
        totals["bytes"] += rec["size"] or 0
        totals["status"][rec["status"]] += 1
        totals["types"][rec["type"].split(" [")[0]] += 1
        if rec["flags"]:
            totals["flagged"] += 1
        if rec["status"] == "mismatch":
            totals["mismatch_pairs"][(rec["ext"], rec["type"].split(" [")[0])] += 1
        if shown(rec, args):
            rows.append(rec)

    if args.output:
        out = open(args.output, "w", encoding="utf-8", newline="")
    else:
        out = sys.stdout
        if hasattr(out, "reconfigure"):
            try:
                out.reconfigure(errors="replace")
            except Exception:
                pass
    try:
        if args.format == "csv":
            write_csv(rows, out, args)
        elif args.format == "json":
            write_json(rows, out, args, totals)
        else:
            write_table(rows, out, args, totals)
    finally:
        if args.output:
            out.close()
    if args.output and args.format != "table":
        write_summary(sys.stderr, totals, argparse.Namespace(summary=False), compact=True)

    if totals["files"] == 0:
        return 2
    return 1 if (totals["status"]["mismatch"] or totals["flagged"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        # Output piped into head/less and closed early.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
