#!/usr/bin/env python3
"""
gcode_to_3w.py - Convert Cura gcode to XYZ Da Vinci .3w v5 format


V5 file layout (Da Vinci Jr. 1.0, firmware 2.4.8):
  0x0000: "3DPFNKG13WTW"    magic (12 bytes)
  0x000C: 01 05 00 00       version
  0x0010: 00 00 00 08       offset to tag (BE, from 0x0010)
  0x0014: 00 00 00 00       padding
  0x0018: "TagEJ256"        encryption marker
  0x0020: uint32 BE         padded header length
  0x0024: 00 00 00 44       offset to CRC area (68, BE)
  0x0028: 00 00 00 01       v5 marker
  0x002C: uint32 BE         CRC32 of encrypted body
  0x0030: zeros             padding
  0x0070: plaintext header  (; key = value, CRLF)
  0x0070+hdrlen: zeros      padding to 0x2000
  0x2000: AES-256-ECB encrypted body (full gcode with header)

Usage:
    python3 gcode_to_3w.py input.gcode [output.3w]
"""

import sys
import os
import struct
import re
from Crypto.Cipher import AES

MAGIC = b"3DPFNKG13WTW"
BODY_OFFSET = 0x2000
BODY_KEY = b"@xyzprinting.com@xyzprinting.com"
ECB_BLOCK = 0x2010
FILE_NUM = "daVinciJR10"

CRC_TABLE = [
    0, 1996959894, 3993919788, 2567524794, 124634137, 1886057615, 3915621685,
    2657392035, 249268274, 2044508324, 3772115230, 2547177864, 162941995,
    2125561021, 3887607047, 2428444049, 498536548, 1789927666, 4089016648,
    2227061214, 450548861, 1843258603, 4107580753, 2211677639, 325883990,
    1684777152, 4251122042, 2321926636, 335633487, 1661365465, 4195302755,
    2366115317, 997073096, 1281953886, 3579855332, 2724688242, 1006888145,
    1258607687, 3524101629, 2768942443, 901097722, 1119000684, 3686517206,
    2898065728, 853044451, 1172266101, 3705015759, 2882616665, 651767980,
    1373503546, 3369554304, 3218104598, 565507253, 1454621731, 3485111705,
    3099436303, 671266974, 1594198024, 3322730930, 2970347812, 795835527,
    1483230225, 3244367275, 3060149565, 1994146192, 31158534, 2563907772,
    4023717930, 1907459465, 112637215, 2680153253, 3904427059, 2013776290,
    251722036, 2517215374, 3775830040, 2137656763, 141376813, 2439277719,
    3865271297, 1802195444, 476864866, 2238001368, 4066508878, 1812370925,
    453092731, 2181625025, 4111451223, 1706088902, 314042704, 2344532202,
    4240017532, 1658658271, 366619977, 2362670323, 4224994405, 1303535960,
    984961486, 2747007092, 3569037538, 1256170817, 1037604311, 2765210733,
    3554079995, 1131014506, 879679996, 2909243462, 3663771856, 1141124467,
    855842277, 2852801631, 3708648649, 1342533948, 654459306, 3188396048,
    3373015174, 1466479909, 544179635, 3110523913, 3462522015, 1591671054,
    702138776, 2966460450, 3352799412, 1504918807, 783551873, 3082640443,
    3233442989, 3988292384, 2596254646, 62317068, 1957810842, 3939845945,
    2647816111, 81470997, 1943803523, 3814918930, 2489596804, 225274430,
    2053790376, 3826175755, 2466906013, 167816743, 2097651377, 4027552580,
    2265490386, 503444072, 1762050814, 4150417245, 2154129355, 426522225,
    1852507879, 4275313526, 2312317920, 282753626, 1742555852, 4189708143,
    2394877945, 397917763, 1622183637, 3604390888, 2714866558, 953729732,
    1340076626, 3518719985, 2797360999, 1068828381, 1219638859, 3624741850,
    2936675148, 906185462, 1090812512, 3747672003, 2825379669, 829329135,
    1181335161, 3412177804, 3160834842, 628085408, 1382605366, 3423369109,
    3138078467, 570562233, 1426400815, 3317316542, 2998733608, 733239954,
    1555261956, 3268935591, 3050360625, 752459403, 1541320221, 2607071920,
    3965973030, 1969922972, 40735498, 2617837225, 3943577151, 1913087877,
    83908371, 2512341634, 3803740692, 2075208622, 213261112, 2463272603,
    3855990285, 2094854071, 198958881, 2262029012, 4057260610, 1759359992,
    534414190, 2176718541, 4139329115, 1873836001, 414664567, 2282248934,
    4279200368, 1711684554, 285281116, 2405801727, 4167216745, 1634467795,
    376229701, 2685067896, 3608007406, 1308918612, 956543938, 2808555105,
    3495958263, 1231636301, 1047427035, 2932959818, 3654703836, 1088359270,
    936918000, 2847714899, 3736837829, 1202900863, 817233897, 3183342108,
    3401237130, 1404277552, 615818150, 3134207493, 3453421203, 1423857449,
    601450431, 3009837614, 3294710456, 1567103746, 711928724, 3020668471,
    3272380065, 1510334235, 755167117
]


def xyz_crc32(data: bytes) -> int:
    num = 0xFFFFFFFF
    for b in data:
        num = (num >> 8) ^ CRC_TABLE[(num ^ b) & 0xFF]
    return num ^ 0xFFFFFFFF


def round_up_16(n: int) -> int:
    return (n + 15) & 0xFFFFFFF0


def pkcs7_pad(data: bytes) -> bytes:
    new_len = round_up_16(len(data) + 1)
    pad_count = new_len - len(data)
    return data + bytes([pad_count] * pad_count)


def check_line_is_header(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return True
    return stripped[0] == ';'


def parse_cura_metadata(gcode: str) -> dict:
    meta = {'print_time': 0, 'total_layers': 0, 'total_filament': 0.0, 'facets': 0}
    # Scan ENTIRE file - Cura puts LAYER_COUNT deep in the gcode, not in the header
    for line in gcode.split('\n'):
        line = line.strip()
        if not line.startswith(';'):
            continue
        try:
            if ';TIME:' in line:
                meta['print_time'] = int(line.split(':',1)[1].strip())
            elif ';LAYER_COUNT:' in line:
                meta['total_layers'] = int(line.split(':',1)[1].strip())
            elif ';Filament used:' in line:
                val = line.split(':',1)[1].strip().rstrip('m').strip()
                meta['total_filament'] = float(val) * 1000.0
            elif 'print_time = ' in line:
                meta['print_time'] = int(line.split('print_time = ')[1].strip())
            elif 'total_layers = ' in line:
                meta['total_layers'] = int(line.split('total_layers = ')[1].strip())
            elif 'total_filament = ' in line:
                meta['total_filament'] = float(line.split('total_filament = ')[1].strip())
        except (ValueError, IndexError):
            pass
    return meta


def process_gcode(gcode: str, file_num: str) -> tuple:
    """Returns (header_text, full_text). Header uses \\r\\n matching XYZware."""
    meta = parse_cura_metadata(gcode)
    lines = gcode.split('\n')

    body_lines = []
    in_header = True
    for line in lines:
        line = line.rstrip('\r')
        if in_header:
            if check_line_is_header(line):
                continue
            else:
                in_header = False
        if not in_header:
            body_lines.append(line)

    # XYZ header with \r\n
    hdr_lines = [
        f"; filename = temp.3w",
        f"; print_time = {meta['print_time']}",
        f"; machine = {file_num}",
        f"; facets = {meta['facets']}",
        f"; total_layers = {meta['total_layers']}",
        f"; version = 18020109",
        f"; total_filament = {meta['total_filament']:.2f}",
    ]
    header_text = "\r\n".join(hdr_lines) + "\r\n"

    # Body: G0 -> G1
    processed = []
    for line in body_lines:
        line = re.sub(r'\bG0\b', 'G1', line)
        line = re.sub(r'\bg0\b', 'g1', line)
        processed.append(line)
    body_text = "\n".join(processed)

    return header_text, header_text + body_text


def encrypt_body_ecb(body_data: bytes) -> bytes:
    padded = pkcs7_pad(body_data)
    cipher = AES.new(BODY_KEY, AES.MODE_ECB)
    result = bytearray(padded)
    body_len = len(padded)
    for offset in range(0, body_len, ECB_BLOCK):
        chunk_len = min(ECB_BLOCK, body_len - offset)
        for sub in range(0, chunk_len, 16):
            block = bytes(result[offset + sub : offset + sub + 16])
            result[offset + sub : offset + sub + 16] = cipher.encrypt(block)
    return bytes(result)


def write_3w_v5(header_text: str, body_enc: bytes, out_path: str):
    """Write .3w matching original XYZware v5 byte layout exactly."""
    header_bytes = header_text.encode('ascii', errors='replace')
    padded_hdr_len = round_up_16(len(header_bytes) + 1)
    pad_count = padded_hdr_len - len(header_bytes)
    padded_header = header_bytes + bytes([pad_count] * pad_count)

    crc = xyz_crc32(body_enc)

    with open(out_path, 'wb') as f:
        # 0x0000: Magic
        f.write(MAGIC)                          # 12 bytes
        # 0x000C: Version
        f.write(b'\x01\x05\x00\x00')           # 4 bytes
        # 0x0010: Offset to tag (BE uint32 = 8, counted from 0x0014)
        # Tag at 0x0014 + 8 = 0x001C
        f.write(struct.pack('>I', 8))           # 4 bytes
        # 0x0014: 8 bytes of zero padding before tag
        f.write(b'\x00' * 8)                    # 8 bytes
        # 0x001C: Tag
        f.write(b'TagEJ256')                    # 8 bytes -> now at 0x0024
        # 0x0024: Header length (padded)
        f.write(struct.pack('>I', len(padded_header)))  # 4 bytes -> 0x0028
        # 0x0028: Offset to CRC area = 0x44 (68)
        f.write(struct.pack('>I', 0x44))        # 4 bytes -> 0x002C
        # 0x002C: v5 marker
        f.write(struct.pack('>I', 1))           # 4 bytes -> 0x0030
        # 0x0030: CRC32
        f.write(struct.pack('>I', crc))         # 4 bytes -> 0x0034
        # 0x0034: Zero padding to 0x0070
        f.write(b'\x00' * (0x0070 - 0x0034))   # 60 bytes
        # 0x0070: Plaintext header
        f.write(padded_header)
        # Pad to 0x2000
        current = f.tell()
        if current < BODY_OFFSET:
            f.write(b'\x00' * (BODY_OFFSET - current))
        elif current > BODY_OFFSET:
            print(f"WARNING: Header overflow! {current} > {BODY_OFFSET}")
        # 0x2000: Encrypted body
        f.write(body_enc)


def convert(gcode_path: str, out_path: str = None):
    if out_path is None:
        out_path = os.path.splitext(gcode_path)[0] + '.3w'

    print(f"Reading: {gcode_path}")
    with open(gcode_path, 'r', errors='replace') as f:
        gcode = f.read()

    meta = parse_cura_metadata(gcode)
    print(f"  Layers: {meta['total_layers']}, Time: {meta['print_time']}s, "
          f"Filament: {meta['total_filament']:.1f}mm")

    header_text, full_text = process_gcode(gcode, FILE_NUM)
    full_bytes = full_text.encode('ascii', errors='replace')
    print(f"  Payload: {len(full_bytes)} bytes")

    print("Encrypting (AES-256-ECB)...")
    body_enc = encrypt_body_ecb(full_bytes)

    print(f"Writing: {out_path}")
    write_3w_v5(header_text, body_enc, out_path)

    size = os.path.getsize(out_path)
    print(f"Done! {size} bytes")
    verify_3w(out_path)
    return out_path


def verify_3w(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    tag_idx = data.find(b'TagEJ256')
    crc_stored = struct.unpack_from('>I', data, 0x30)[0]
    crc_calc = xyz_crc32(data[BODY_OFFSET:])
    hdr = data[0x0070:0x0070+80].split(b'\x00')[0].decode('ascii', errors='replace')
    first_line = hdr.split('\r\n')[0] if '\r\n' in hdr else hdr[:40]
    print(f"  v{data[13]}, Tag@0x{tag_idx:04X}, CRC={'OK' if crc_stored==crc_calc else 'MISMATCH!'}")
    print(f"  Header: \"{first_line}\"")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} input.gcode [output.3w]")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
