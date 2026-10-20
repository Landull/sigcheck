# sigcheck

A file signature checker. Point it at a folder or mounted image and it reads the first bytes of every file (its magic number), works out what each file really is, and flags the ones whose extension lies: an executable renamed `.jpg`, a ZIP saved as `.pdf`, a spreadsheet hiding as `.txt`, or a `.docx` that's nothing but encrypted noise.

It also looks for the tricks that usually come with a disguised file: data hidden after the end of an image, PDF or ZIP, Office files with macros, PDFs with JavaScript or launch actions, small archives carrying executables, double extensions, and right-to-left override characters in file names.

No dependencies. Just Python 3.8+ and the standard library. It pairs with [hashcheck](https://github.com/Landull/hashcheck), [metacheck](https://github.com/Landull/metacheck), [iocheck](https://github.com/Landull/iocheck), [histcheck](https://github.com/Landull/histcheck) and [timecheck](https://github.com/Landull/timecheck).

## What it recognizes

Over 100 file types, by content rather than name. Run `python3 sigcheck.py --types` for the full list.

| Kind | Examples |
|---|---|
| Executables | PE (EXE, DLL, drivers, EFI, with architecture and .NET noted), ELF, Mach-O, Java class, DEX, WebAssembly, scripts with a `#!` line, LNK shortcuts, CHM, MSI, SWF |
| Documents | PDF, Word/Excel/PowerPoint in both the old (OLE) and new (OOXML) formats, password-protected Office files, OpenDocument, RTF, EPUB, OneNote, Outlook MSG, PostScript |
| Images | JPEG, PNG, GIF, BMP, TIFF and camera raw (DNG, NEF, CR2, CR3, ARW, RAF and more), WebP, HEIC, AVIF, PSD, ICO, SVG |
| Audio and video | MP4, MOV, M4A, 3GP, MKV, WebM, AVI, WAV, FLAC, Ogg, MP3, WMV, FLV, MPEG |
| Archives | ZIP and everything built on it (JAR, APK, IPA, MSIX, wheels, VSIX, NuGet), RAR, 7-Zip, gzip, bzip2, xz, Zstandard, CAB, tar, deb, RPM |
| Disk images | ISO, VHD, VHDX, VMDK, QCOW2, VDI, DMG, E01, Ex01, L01, AFF, LUKS, BitLocker |
| Forensic artifacts | SQLite (browser history and the like), registry hives, EVTX and EVT logs, prefetch, ESE databases, jump lists, Thumbs.db, minidumps, hibernation files, pcap and pcapng, PST/OST, KeePass, binary plists |

ZIP and OLE files are opened far enough to tell a `.docx` from a `.xlsx` from an `.apk`, so renaming one Office format as another is caught too. Text files have no magic number, so they're labeled by kind (script, HTML, XML, SVG, plist, PEM) and only flagged when they sit behind a binary extension.

## What it flags

- **Mismatches**: content that doesn't fit the extension, or a known extension (`.jpg`, `.docx`, `.pdf`...) with no matching signature at all
- **Executable content behind a non-executable extension**, or with no extension at all
- **Data after the end of a file**: bytes past a PNG's `IEND`, a JPEG's end-of-image marker, a GIF trailer, a ZIP's end record or a PDF's last `%%EOF`, with a note when that data starts like an executable or archive
- **High-entropy unknown files** that look encrypted, which is what ransomware leaves behind, and files that are all zeros
- **Macros**: `vbaProject.bin` in OOXML files and VBA storages in old Office files, plus embedded OLE packages
- **Active PDF content**: `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/XFA` and `/SubmitForm`, with `/OpenAction` and `/AA` counted alongside
- **Archives built to deliver something**: small ZIPs holding `.exe`, `.js`, `.lnk` and similar files, and password-protected entries
- **Name tricks**: double extensions like `invoice.pdf.exe`, right-to-left override characters (shown escaped, with how the name would appear), names ending in a space or dot, and long runs of spaces before the extension

## How it handles evidence

- **Reading doesn't change access times on Linux.** Files are opened read-only with `O_NOATIME` when the system allows it. I checked by setting old access times on a test folder, running a full scan with `--hash`, and comparing; nothing changed, while a plain `cat` of one file did change it.
- **Only what's needed is read.** Most files are identified from their first 38 KB. Images, PDFs and ZIPs are read further to find their real end, up to `--max-scan` (256 MB by default).
- **It never follows symlinks** and skips devices, pipes and sockets, since reading those can block or change state.
- **Hidden characters can't scramble the output.** Direction-changing characters in names are printed as `<U+202E>` and the like in every format.

## Usage

```
python3 sigcheck.py /Volumes/Evidence/Users
```

By default only problems are shown: mismatches and anything flagged. Some real uses:

```
# Every file, with its real type
python3 sigcheck.py /Volumes/Evidence/Users --all

# Just the mismatches, with SHA-256 for the case notes
python3 sigcheck.py /Volumes/Evidence/Users --status mismatch --hash

# What's in this folder, and which extensions are lying about what
python3 sigcheck.py /Volumes/Evidence/Users/bob/Downloads --summary

# A single suspicious attachment
python3 sigcheck.py Scan_2026.pdf

# Skip noise
python3 sigcheck.py /Volumes/Evidence -x 'Windows' -x '*.tmp'

# Spreadsheet for case notes, or JSON for scripts
python3 sigcheck.py /Volumes/Evidence/Users --all --hash -f csv -o signatures.csv
python3 sigcheck.py /Volumes/Evidence/Users -f json -o signatures.json
```

On Windows, use `python` instead of `python3`.

## Options

| Flag | Description |
|---|---|
| `-a, --all` | show every file, not just problems |
| `--status STATUS` | only `match`, `mismatch`, `unknown`, `empty` or `error` files (repeatable) |
| `--flagged` | only files with findings |
| `-x, --exclude GLOB` | skip files and folders matching GLOB (repeatable) |
| `-n, --no-recurse` | don't descend into subfolders |
| `--hash` | add the SHA-256 of each file |
| `--max-scan MB` | largest file to read in full when looking for trailing data and PDF keywords (default 256) |
| `--summary` | add counts of content types and of each extension-to-content mismatch |
| `--types` | list the file types sigcheck recognizes |
| `-f, --format` | `table` (default), `csv` or `json` |
| `-o, --output FILE` | write output to a file |

## Example

```
STATUS    TYPE                                   EXT    PATH
MISMATCH  unknown high-entropy data              .docx !bob/Documents/contract.docx
                                                        ! no Word document (OOXML) signature: content doesn't match .docx
                                                        ! high entropy (7.98 bits/byte): encrypted or compressed
OK        PDF document                           .pdf  !bob/Documents/form.pdf
                                                        ! PDF has active content: /JavaScript x1, /JS x1, /OpenAction x1
OK        Word document (OOXML) [18 entries]     .docx !bob/Documents/invoice.docx
                                                        ! contains VBA macros (vbaProject.bin)
MISMATCH  Excel workbook (OOXML) [9 entries]     .txt  !bob/Documents/notes.txt
                                                        ! content is Excel workbook (OOXML), not .txt
MISMATCH  HTML [ASCII]                           .doc  !bob/Documents/page.doc
                                                        ! HTML content, not Word document
OK        PE executable (EXE, x64) [GUI]         .exe  !bob/Downloads/Invoice_0412.pdf.exe
                                                        ! double extension (.pdf.exe)
OK        PE executable (EXE, x64) [GUI]         .exe  !bob/Downloads/Invoice_<U+202E>fdp.exe
                                                        ! name contains a right-to-left override; it displays as "Invoice_exe.pdf"
MISMATCH  ZIP archive [1 entry]                  .pdf  !bob/Downloads/Scan_2026.pdf
                                                        ! content is ZIP archive, not .pdf
                                                        ! small archive holding executable/script files: Scan_2026.pdf.exe
MISMATCH  ELF executable [shared object or PIE]  .mp3  !bob/Downloads/update.mp3
                                                        ! content is ELF executable, not .mp3
                                                        ! executable content behind a .mp3 extension
OK        JPEG image                             .jpg  !bob/Pictures/beach.jpg
                                                        ! 124 B of data after the end of the JPEG (starts like: ZIP archive)
MISMATCH  PE executable (EXE, x64) [GUI]         .jpg  !bob/Pictures/holiday.jpg
                                                        ! content is PE executable (EXE, x64), not .jpg
                                                        ! executable content behind a .jpg extension
OK        PNG image                              .png  !bob/Pictures/logo.png
                                                        ! 4.9 KB of data after the end of the PNG (starts like: PE/DOS executable)
MISMATCH  PNG image                              .jpg  !bob/Pictures/really_png.jpg
                                                        ! content is PNG image, not .jpg
MISMATCH  script (/bin/bash) [ASCII]             .png  !bob/Pictures/wallpaper.png
                                                        ! content is script (/bin/bash), not .png
                                                        ! executable content behind a .png extension

Checked 28 files (648.2 KB): 19 match, 8 mismatch, 0 unknown, 1 empty. 14 flagged.
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Every file checked out, nothing flagged |
| `1` | At least one mismatch or finding |
| `2` | Bad input (missing path, or no files to check) |

## Forensic notes

- **Work on copies.** Access times are protected on Linux, but Windows and macOS may still update them depending on settings, and listing a folder can update the folder's own times. Run it against a forensic image or a write-blocked copy.
- **A mismatch is a lead, not a verdict.** Plenty of software uses odd names for ordinary files: a PNG saved as `.jpg`, a ZIP-based format with its own extension, an HTML page saved as `.doc` by an old export. Extensions sigcheck doesn't know are reported as a match unless the content is executable, so it stays quiet on app-specific files.
- **Trailing data has innocent causes too.** Some cameras and editors leave padding or extra data after an image ends, PDFs grow through incremental saves, and signed ZIPs can carry comments. Look at what the extra data is before calling it hidden.
- **PDF keywords can be obfuscated.** A name like `/J#61vaScript` hides `/JavaScript` from simple scans. For a suspicious PDF, follow up with a full parser like pdfid or pdf-parser.
- **Limits.** Short signatures (MP3 frames, AAC, TrueType, TGA) are only trusted when the extension already agrees. Encrypted containers like VeraCrypt volumes have no signature by design and show up as high-entropy unknown data. Split archives, carved fragments and damaged files may not identify cleanly.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s forensics toolkit.
