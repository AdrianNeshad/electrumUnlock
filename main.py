import base64
import hashlib
import hmac
import json
import sys
import zlib
from pathlib import Path

WALLET_FILENAME = "default_wallet"
PASSWORD_FILENAME = "password.txt"
OUTPUT_SUFFIX = ".decrypted.json"

# =====================================================================
# secp256k1 - kurvparametrar (offentlig standard, samma kurva som Bitcoin)
# =====================================================================
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def _inv(a, m):
    return pow(a, m - 2, m)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _privkey_to_pubkey(d):
    return _scalar_mult(d, G)


def _decompress_pubkey(data):
    prefix = data[0]
    x = int.from_bytes(data[1:33], "big")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y % 2 == 0) != (prefix == 2):
        y = P - y
    return (x, y)


def _compress_pubkey(point):
    x, y = point
    prefix = 2 if y % 2 == 0 else 3
    return bytes([prefix]) + x.to_bytes(32, "big")


# =====================================================================
# AES-128 (dekryptering), ren Python, enligt NIST FIPS-197
# =====================================================================
_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _key_expansion(key):
    nk, nr = 4, 10
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
    round_keys = []
    for r in range(nr + 1):
        rk = w[4 * r:4 * r + 4]
        round_keys.append([b for col in rk for b in col])
    return round_keys


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xff


def _add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]


def _inv_sub_bytes(state):
    return [_INV_SBOX[b] for b in state]


def _inv_shift_rows(state):
    s = state[:]
    out = s[:]
    for r in range(1, 4):
        row = [s[c * 4 + r] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            out[c * 4 + r] = row[c]
    return out


def _inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        a = state[c * 4:c * 4 + 4]
        out[c * 4 + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        out[c * 4 + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        out[c * 4 + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        out[c * 4 + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
    return out


def _aes128_decrypt_block(block, round_keys):
    state = list(block)
    state = _add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return bytes(state)


def _aes128_cbc_decrypt(ciphertext, key, iv):
    if len(ciphertext) % 16 != 0 or len(ciphertext) == 0:
        raise ValueError("Ogiltig ciphertext-längd (inte multipel av 16).")
    round_keys = _key_expansion(key)
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _aes128_decrypt_block(block, round_keys)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out += plain_block
        prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or pad > len(out):
        raise ValueError("Ogiltig PKCS7-padding efter dekryptering (fel lösenord?).")
    return out[:-pad]


# =====================================================================
# AES-256 (dekryptering), ren Python, enligt NIST FIPS-197
# Används för det INRE lagret som skyddar seed/xprv i keystore.
# =====================================================================
_RCON256 = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]


def _key_expansion_256(key):
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON256[i // nk - 1]
        elif i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
    round_keys = []
    for r in range(nr + 1):
        rk = w[4 * r:4 * r + 4]
        round_keys.append([b for col in rk for b in col])
    return round_keys


def _aes256_decrypt_block(block, round_keys):
    nr = 14
    state = list(block)
    state = _add_round_key(state, round_keys[nr])
    for rnd in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return bytes(state)


def _aes256_cbc_decrypt(ciphertext, key, iv):
    if len(ciphertext) % 16 != 0 or len(ciphertext) == 0:
        raise ValueError("Ogiltig ciphertext-längd (inte multipel av 16).")
    round_keys = _key_expansion_256(key)
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _aes256_decrypt_block(block, round_keys)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out += plain_block
        prev = block
    pad = out[-1]
    if pad < 1 or pad > 16 or pad > len(out):
        raise ValueError("Ogiltig PKCS7-padding (fel lösenord, eller fältet var inte krypterat).")
    return out[:-pad]


def pw_decode(encoded_str: str, password: str) -> str:
    """Dekrypterar Electrums inre fält-nivå-kryptering (t.ex. keystore['seed']).
    Nyckel = dubbel SHA-256 av lösenordet. Format: base64(iv[16] + AES-256-CBC-ciphertext)."""
    secret = hashlib.sha256(hashlib.sha256(password.encode("utf-8")).digest()).digest()
    raw = base64.b64decode(encoded_str)
    if len(raw) < 32:
        raise ValueError("För kort data för att vara ett pw_encode-krypterat fält.")
    iv, ciphertext = raw[:16], raw[16:]
    plaintext = _aes256_cbc_decrypt(ciphertext, secret, iv)
    return plaintext.decode("utf-8")


# =====================================================================
# Electrum-specifik logik
# =====================================================================
def get_eckey_from_password(password: str) -> int:
    """Samma härledning som Electrum använder: PBKDF2-HMAC-SHA512,
    1024 iterationer, tomt salt -> reducera modulo kurvans ordning."""
    secret = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), b"", iterations=1024)
    d = int.from_bytes(secret, "big") % N
    return d


def ecies_decrypt_message(privkey_int: int, encrypted_b64: str, magic: bytes = b"BIE1"):
    """Dekrypterar Electrums 'BIE1'-ECIES-format. Returnerar (plaintext, mac_ok)."""
    raw = base64.b64decode(encrypted_b64)
    if raw[:4] != magic:
        raise ValueError(f"Fel magic bytes: förväntade {magic!r}, fick {raw[:4]!r}")
    ephem_pub_bytes = raw[4:37]
    ciphertext = raw[37:-32]
    mac_received = raw[-32:]

    ephem_point = _decompress_pubkey(ephem_pub_bytes)
    shared_point = _scalar_mult(privkey_int, ephem_point)
    key_material = hashlib.sha512(_compress_pubkey(shared_point)).digest()
    iv, key_e, key_m = key_material[0:16], key_material[16:32], key_material[32:64]

    mac_data = raw[:-32]
    mac_calc = hmac.new(key_m, mac_data, hashlib.sha256).digest()
    mac_ok = hmac.compare_digest(mac_calc, mac_received)

    plaintext = _aes128_cbc_decrypt(ciphertext, key_e, iv)
    return plaintext, mac_ok


def decrypt_wallet_file(raw_file_content: str, password: str) -> str:
    """Tar den råa (base64) filinnehållet + lösenord, returnerar dekrypterad JSON-text."""
    magic = base64.b64decode(raw_file_content)[:4]
    if magic == b"BIE2":
        raise ValueError(
            "Filen är krypterad med BIE2 (hårdvaruplånbok/xpub-baserat lösenord), "
            "inte ett vanligt användarlösenord. Detta skript stödjer bara BIE1."
        )
    if magic != b"BIE1":
        raise ValueError("Filen verkar inte vara krypterad (ingen BIE1/BIE2-magic hittad).")

    d = get_eckey_from_password(password)
    compressed_bytes, mac_ok = ecies_decrypt_message(d, raw_file_content, magic=b"BIE1")
    if not mac_ok:
        raise ValueError("MAC-verifiering misslyckades — lösenordet är troligen fel.")
    try:
        json_bytes = zlib.decompress(compressed_bytes)
    except zlib.error as e:
        raise ValueError(f"zlib-dekomprimering misslyckades (lösenordet är troligen fel): {e}")
    return json_bytes.decode("utf-8")


# =====================================================================
# Självtest mot en publikt känd Electrum BIE1-testvektor
# =====================================================================
def self_test():
    # Test 1: fil-nivå ECIES ("BIE1"), mot publikt känd testvektor
    privkey_hex = "a1b50c4d420b20059b01e7eea3b3d8a5e943728dfedf962628ca18d04bfa2cfc"
    ciphertext_b64 = (
        "QklFMQMFmPdvjFe8Wfo+JWmTpo+33LXc+4G8ThfaucU72kieb6lWEv4layTb0x5t"
        "zpi6lA2it8rO/ELrXomJqC53uBOd+DZSzDhCSpK6SwR+Itt+Pw=="
    )
    expected = b"hello"
    plaintext, mac_ok = ecies_decrypt_message(int(privkey_hex, 16), ciphertext_b64)
    if plaintext != expected or not mac_ok:
        sys.exit(
            "INTERNT SJÄLVTEST MISSLYCKADES (fil-nivå-kryptot) — kryptoimplementationen "
            "i detta skript ger fel resultat. Kör INTE detta mot din riktiga wallet-fil. "
            f"(fick plaintext={plaintext!r}, mac_ok={mac_ok})"
        )

    # Test 2: AES-256-kärnan, mot officiellt NIST FIPS-197-testvektor
    nist_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nist_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    nist_ct_expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    rks = _key_expansion_256(nist_key)
    nist_pt_roundtrip = _aes256_decrypt_block(nist_ct_expected, rks)
    if nist_pt_roundtrip != nist_pt:
        sys.exit(
            "INTERNT SJÄLVTEST MISSLYCKADES (AES-256-kärnan) — kör INTE detta mot din "
            "riktiga wallet-fil."
        )


# =====================================================================
# Huvudprogram
# =====================================================================
def main():
    self_test()  # kör alltid självtestet först — avbryter om krypto-logiken är trasig

    script_dir = Path(__file__).resolve().parent
    wallet_path = script_dir / WALLET_FILENAME
    password_path = script_dir / PASSWORD_FILENAME
    output_path = script_dir / f"{WALLET_FILENAME}{OUTPUT_SUFFIX}"

    if not wallet_path.exists():
        sys.exit(f"Hittar ingen wallet-fil på: {wallet_path}\n"
                  f"Lägg din fil i samma mapp och döp den till '{WALLET_FILENAME}'.")
    if not password_path.exists():
        sys.exit(f"Hittar ingen '{PASSWORD_FILENAME}' i: {script_dir}")

    password = password_path.read_text(encoding="utf-8").rstrip("\n").rstrip("\r")
    if not password:
        sys.exit(f"'{PASSWORD_FILENAME}' verkar vara tom.")

    raw_content = wallet_path.read_text(encoding="utf-8").strip()

    print("Självtest av kryptoimplementationen: OK")
    print(f"Läser wallet-fil: {wallet_path}")
    print("Försöker dekryptera med lösenordet från password.txt ...")

    try:
        decrypted_text = decrypt_wallet_file(raw_content, password)
    except Exception as e:
        sys.exit(f"Dekryptering misslyckades: {e}")

    try:
        data = json.loads(decrypted_text)
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except json.JSONDecodeError:
        output_path.write_text(decrypted_text, encoding="utf-8")
        data = None

    print(f"\n✅ Klart! Dekrypterat innehåll sparat till:\n   {output_path}\n")

    if data is not None:
        print("Kort sammanfattning:")
        print(f"  wallet_type:  {data.get('wallet_type', 'okänd')}")
        print(f"  seed_version: {data.get('seed_version', 'okänd')}")

        # Samla ihop alla keystores. Vanliga plånböcker har ett fält "keystore",
        # multisig-plånböcker har flera under "x1/", "x2/", "x3/" osv.
        keystores = []
        if "keystore" in data:
            keystores.append(("keystore", data["keystore"]))
        for k, v in data.items():
            if k.startswith("x") and k.endswith("/") and isinstance(v, dict):
                keystores.append((k, v))

        if not keystores:
            print("  Ingen keystore hittades i filen (kan vara en watching-only-plånbok).")

        file_needs_rewrite = False
        for name, ks in keystores:
            raw_seed = ks.get("seed")
            if not raw_seed:
                print(f"  {name}: ingen seed-fras (t.ex. importerade nycklar eller hårdvaruplånbok)")
                continue

            # Seed-fältet är i sig krypterat separat (pw_encode/pw_decode-lagret).
            # Om det redan råkar vara vanlig text (sällsynt, äldre okrypterade
            # wallets) används det direkt.
            try:
                seed_plain = pw_decode(raw_seed, password)
            except Exception:
                seed_plain = raw_seed  # var troligen redan klartext

            print(f"\n  Seed-fras ({name}):")
            print(f"    {seed_plain}")

            # Lägg till den dekrypterade seeden i data-strukturen, så den
            # även hamnar i output-JSON-filen (utöver terminalutskriften).
            ks["seed_decrypted"] = seed_plain
            file_needs_rewrite = True

            raw_passphrase = ks.get("passphrase")
            if raw_passphrase:
                try:
                    passphrase_plain = pw_decode(raw_passphrase, password)
                except Exception:
                    passphrase_plain = raw_passphrase
                print(f"    (obs: seeden har även en extra passphrase satt: {passphrase_plain})")
                ks["passphrase_decrypted"] = passphrase_plain

        if file_needs_rewrite:
            output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"\n  (Filen {output_path.name} har uppdaterats med dekrypterad(e) seed-fras(er).)")

            # Skapa dessutom en separat .txt-fil som bara innehåller seed-frasen/frasrna.
            seed_txt_path = script_dir / f"{WALLET_FILENAME}.seed.txt"
            lines = []
            for name, ks in keystores:
                seed_plain = ks.get("seed_decrypted")
                if seed_plain:
                    lines.append(f"{name}: {seed_plain}" if len(keystores) > 1 else seed_plain)
                pass_plain = ks.get("passphrase_decrypted")
                if pass_plain:
                    lines.append(f"passphrase ({name}): {pass_plain}")
            seed_txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"  Seed-frasen har även sparats separat i klartext till:\n    {seed_txt_path}")

    print("\n⚠️  Filen ovan innehåller känslig information i klartext.")
    print("    Radera den (och password.txt) säkert när du kopierat det du behöver.")


if __name__ == "__main__":
    main()