<h1 id="title">Electrum Wallet Unlock</h1>

1.  The script reads the wallet file in `case/default_wallet`, this file is usually found in <code>%appdata%/Electrum/wallets</code>.
2.  It then tries the passwords from `passwords.txt`.
3.  If a password is correct it decrypts the wallet-file and extracts the seed phrase in `output/default_wallet.json`.

The repository already includes a `default_wallet` file and the corresponding password in `passwords.txt` to test out the script.

### **Run the script**

```
python3 main.py
```

### **Användaravtal:**

*   Vid lyckad extrahering av `default_wallet`-fil är användaren skyldig Adrian (repository owner) en öl.

