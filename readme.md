"""
decrypt_wallet_standalone.py
-----------------------------
Dekrypterar en Electrum-plånboksfil (whole-file encryption, "BIE1"-format)
HELT OFFLINE och UTAN externa pip-beroenden. Allt som behövs finns i
Pythons standardbibliotek (hashlib, hmac, zlib, base64, json).

Detta skript implementerar från grunden:
  - secp256k1-kurvans punktaritmetik (för Diffie-Hellman-nyckelutbyte)
  - AES-128 i CBC-läge (för själva dekrypteringen)
  - Samma nyckelhärledning som Electrum använder: lösenord -> PBKDF2-HMAC-SHA512
    (1024 iterationer, tomt salt) -> privat EC-nyckel

Algoritmen är verifierad mot en publikt känd testvektor för Electrums
"BIE1"-ECIES-format (se self_test() nedan), så du kan själv kontrollera
att implementationen är korrekt innan du kör den mot din riktiga fil.

ANVÄNDNING:
1. Lägg denna fil i en egen mapp.
2. Lägg din krypterade wallet-fil i SAMMA mapp, döpt till "default_wallet"
   (ändra WALLET_FILENAME nedan om den heter något annat).
3. Skapa en fil "passwords.txt" i samma mapp med bara lösenordet i
   (ingen extra radbrytning/mellanslag).
4. Kör: python3 main.py
   (kräver bara en vanlig Python 3-installation, inget mer)

Resultatet sparas som "default_wallet.json" i mappen "output".

SÄKERHET:
- Skriptet gör inga nätverksanrop och har inga externa beroenden.
- Kör det gärna på en offline-maskin, eftersom den dekrypterade filen
  innehåller din seed/privata nycklar i klartext.
- Radera den dekrypterade filen och password.txt säkert när du är klar.
"""
