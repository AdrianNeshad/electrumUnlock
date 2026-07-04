#!/usr/bin/env python3
"""
decrypt_wallet.py
------------------
Dekrypterar en Electrum-plånboksfil offline med hjälp av electrum-biblioteket.

ANVÄNDNING:
1. Lägg denna fil i en egen mapp.
2. Lägg din krypterade wallet-fil i SAMMA mapp och döp den till "default_wallet"
   (eller ändra WALLET_FILENAME nedan om den heter något annat).
3. Skapa en fil "password.txt" i samma mapp som bara innehåller lösenordet
   (ingen extra radbrytning eller mellanslag).
4. Kör: python3 decrypt_wallet.py

Resultatet skrivs till "default_wallet.decrypted.json" i samma mapp,
och en kort sammanfattning skrivs ut i terminalen.

SÄKERHET:
- Skriptet gör inga nätverksanrop. Allt sker lokalt.
- Den dekrypterade filen innehåller din seed/privata nycklar i klartext.
  Radera den (säkert) så fort du kopierat det du behöver, och kör helst
  det här på en offline-maskin / i en USB-startad Linux-miljö.
- password.txt bör raderas efteråt av samma anledning.

BEROENDEN:
    pip install electrum
(detta installerar endast python-paketet/biblioteket, ingen GUI startas)
"""

import json
import sys
from pathlib import Path

WALLET_FILENAME = "default_wallet"
PASSWORD_FILENAME = "password.txt"
OUTPUT_SUFFIX = ".decrypted.json"


def main():
    script_dir = Path(__file__).resolve().parent
    wallet_path = script_dir / WALLET_FILENAME
    password_path = script_dir / PASSWORD_FILENAME
    output_path = script_dir / f"{WALLET_FILENAME}{OUTPUT_SUFFIX}"

    if not wallet_path.exists():
        sys.exit(f"Hittar ingen wallet-fil på: {wallet_path}\n"
                  f"Lägg din fil i samma mapp och döp den till '{WALLET_FILENAME}', "
                  f"eller ändra WALLET_FILENAME i skriptet.")

    if not password_path.exists():
        sys.exit(f"Hittar ingen '{PASSWORD_FILENAME}' i: {script_dir}\n"
                  f"Skapa filen och lägg ditt lösenord i den (utan extra radbrytningar).")

    password = password_path.read_text(encoding="utf-8").rstrip("\n").rstrip("\r")
    if not password:
        sys.exit(f"'{PASSWORD_FILENAME}' verkar vara tom.")

    try:
        from electrum import storage
    except ImportError:
        sys.exit(
            "Modulen 'electrum' är inte installerad.\n"
            "Kör: pip install electrum\n"
            "(installerar endast biblioteket, startar ingen app)"
        )

    print(f"Läser wallet-fil: {wallet_path}")
    ws = storage.WalletStorage(str(wallet_path))

    if not ws.is_encrypted():
        sys.exit("Filen verkar inte vara krypterad — inget att dekryptera.")

    print("Försöker dekryptera med angivet lösenord...")
    try:
        ws.decrypt(password)
    except Exception as e:
        sys.exit(f"Dekryptering misslyckades (troligen fel lösenord): {e}")

    decrypted_text = ws.decrypted
    if not decrypted_text:
        sys.exit("Dekrypteringen gav inget innehåll — något gick fel.")

    # Försök snygga till som JSON, annars spara raw text
    try:
        data = json.loads(decrypted_text)
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except json.JSONDecodeError:
        output_path.write_text(decrypted_text, encoding="utf-8")
        data = None

    print(f"\n✅ Klart! Dekrypterat innehåll sparat till:\n   {output_path}\n")

    if data is not None:
        wallet_type = data.get("wallet_type", "okänd")
        seed_version = data.get("seed_version", "okänd")
        keystore = data.get("keystore", {})
        has_seed = bool(keystore.get("seed"))
        print("Kort sammanfattning:")
        print(f"  wallet_type:  {wallet_type}")
        print(f"  seed_version: {seed_version}")
        print(f"  har seed:     {'ja' if has_seed else 'nej / okänt fält'}")

    print("\n⚠️  Kom ihåg: filen ovan innehåller känslig information i klartext.")
    print("    Radera den (och password.txt) säkert när du kopierat det du behöver.")


if __name__ == "__main__":
    main()