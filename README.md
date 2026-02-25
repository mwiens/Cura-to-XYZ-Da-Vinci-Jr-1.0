# Cura-to-XYZ-Da-Vinci-Jr-1.0

A script and short manual on how to use Cura to create gcode and convert it to XYZ Da Vinci Jr. 1.0 printer (3w file).

Convert Cura/Slic3r G-code files to XYZ Da Vinci `.3w` format - no XYZ softwareware needed. It helps to use more powerfull software for additional supports, tweaks and better prints on XYZ Da Vinci printer.

Built for the **Da Vinci Jr. 1.0** (firmware 2.4.8), but should work with other Da Vinci printers that use the v5 `.3w` format. Tested with Cura 5.11.

## How it works

XYZ printers refuse standard G-code and require their proprietary `.3w` format: a binary container with metadata headers and AES-256-ECB encrypted G-code. This tool produces `.3w` files that are byte-compatible with XYZware output.

The encryption keys and file format were originally taken from the [miniMover](https://github.com/reality-boy/miniMover) source code, combined with binary analysis of original XYZware output files (from "XYZ Print" software).

## Files

| File | Description |
|------|-------------|
| `gcode_to_3w.py` | Python converter - the core tool |
| `gcode-watcher.sh` | Linux file watcher for automatic conversion (optional)|
| `gcode-watcher.service` | systemd user service for autostart (optional) |

## Quick start

### One-time conversion

```bash
pip install pycryptodome
python3 gcode_to_3w.py model.gcode
```
(You can also use requirements.txt)
This creates `model.3w` next to the input file. Transfer it to your printer via USB stick or XYZware's import function.

You can also specify an output path:

```bash
python3 gcode_to_3w.py model.gcode /path/to/output.3w
```

## (Optional) Linux - Automatic conversion

Automatically convert any `.gcode` file dropped into a watched folder.
Unfortunately it is not possible to use Cura's post process trigger, as the output for the file is in a binary format and can not be processed by Cura after the conversion.

### Dependencies

```bash
# Debian/Ubuntu/Mint
sudo apt install inotify-tools
pip install pycryptodome
```

### Install

```bash
mkdir -p ~/.bin
cp gcode_to_3w.py gcode-watcher.sh ~/.bin/
chmod +x ~/.bin/gcode_to_3w.py ~/.bin/gcode-watcher.sh
```

### Configure

Edit `gcode-watcher.sh` to set your watch directory (default: `~/cura_to_3w`):

```bash
WATCH_DIR="${1:-$HOME/cura_to_3w}"
```

To auto-delete `.gcode` files after successful conversion:

```bash
DELETE_GCODE=true
```

### Run manually

```bash
~/.bin/gcode-watcher.sh
```

Or specify a custom directory:

```bash
~/.bin/gcode-watcher.sh ~/my-prints
```

### Run as a service (autostart)

Edit `gcode-watcher.service` and adjust the `ExecStart` path to match your install location:

```ini
ExecStart=/home/YOUR_USERNAME/.bin/gcode-watcher.sh
```

Then install and enable:

```bash
mkdir -p ~/.config/systemd/user
cp gcode-watcher.service ~/.config/systemd/user/
systemctl --user enable --now gcode-watcher
```

Monitor the service:

```bash
journalctl --user -u gcode-watcher -f
```

### Workflow

1. Slice your model in Cura
2. Save `.gcode` to the watched folder (e.g. `~/cura_to_3w`)
3. The watcher auto-converts it to `.3w`
4. A desktop notification appears when done
5. Transfer the `.3w` to the printer

## Windows - Manual conversion

The Python converter works on Windows without the file watcher. The watcher script uses `inotifywait` which is Linux-only, but the converter itself is cross-platform. (Or you find a PS based file watcher to automate it)

### Dependencies

Install Python 3.8+ from [python.org](https://www.python.org/downloads/), then:

```cmd
pip install pycryptodome
```

### Usage

```cmd
python gcode_to_3w.py model.gcode
```

Or with a specific output path:

```cmd
python gcode_to_3w.py C:\Users\You\Desktop\model.gcode C:\Users\You\Desktop\model.3w
```

### Tip: Drag & drop batch file

Create a file called `convert.bat` in the same folder as `gcode_to_3w.py`:

```bat
@echo off
python "%~dp0gcode_to_3w.py" %1
pause
```

Then drag and drop any `.gcode` file onto `convert.bat` to convert it.

## Info - Cura settings for Da Vinci Jr. 1.0

These settings match the XYZware defaults and are known to work well:
You can tweak the speeds up to 50-55 for infill or play around to find best settings by trial and error.

| Setting | Value |
|---------|-------|
| Nozzle Size | 0.40 mm |
| Compatible Material Diameter | **1.75 mm** |
| Layer Height | 0.30 mm |
| Initial Layer Height | 0.35 mm |
| Line Width | 0.40 mm |
| Wall Line Count | 2 |
| Infill Density | 10–20% |
| Infill Pattern | Lines |
| Print Speed | 35 mm/s |
| Wall Speed | 15 mm/s |
| Top/Bottom Speed | 5 mm/s |
| Initial Layer Speed | 5–10 mm/s |
| Travel Speed | 100 mm/s |
| Print Temperature | 200–210 °C |
| Retraction Distance | 4.0 mm |
| Retraction Speed | 15 mm/s |
| Build Plate Adhesion | Brim (10 mm) |

> **Important:** Make sure *Compatible Material Diameter* is set to **1.75 mm** in Cura's machine settings (Preferences → Printers → Machine Settings → Extruder). The default for some Da Vinci profiles on the internet is 2.85 mm, which causes severe under-extrusion.

## .3w file format (v5)

For anyone interested in the internals:

```
Offset  Content
------  -------
0x0000  "3DPFNKG13WTW"         12-byte magic
0x000C  01 05 00 00             File ID + version (v5)
0x0010  00 00 00 08             Offset to tag (big-endian, from 0x0014)
0x0014  00 00 00 00             Padding
0x0018  00 00 00 00             Padding
0x001C  "TagEJ256"              AES-256-ECB encryption marker
0x0024  uint32 BE               Padded header data length
0x0028  00 00 00 44             Offset to CRC area (68)
0x002C  00 00 00 01             v5 format marker
0x0030  uint32 BE               CRC32 of encrypted body
0x0034  zeros                   Padding
0x0070  Plaintext header        "; key = value\r\n" metadata
        zeros                   Padding to 0x2000
0x2000  Encrypted body          AES-256-ECB, key: "@xyzprinting.com" x2
```

The body is the full G-code (header + commands), PKCS7-padded to a 16-byte boundary, encrypted with AES-256-ECB using the key `@xyzprinting.com@xyzprinting.com` in 0x2010-byte chunks. The CRC32 uses XYZ's custom lookup table (identical to standard CRC32 table but with their own implementation).

## Credits

- [miniMover](https://github.com/reality-boy/miniMover) by reality-boy

## License

MIT
