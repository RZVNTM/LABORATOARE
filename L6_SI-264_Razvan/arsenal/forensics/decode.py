import argparse
import base64
import hashlib
import json
import re
import sys
from urllib.parse import unquote

# A1 & A4: Verificare dacă toți octeții sunt caractere ASCII imprimabile (32..126)
def citibil(b: bytes) -> bool:
    return all(32 <= c < 127 for c in b)

# A2: Recunoaște stratul după formă/alfabet
def ghici_strat(s: str) -> str:
    s_clean = s.strip()
    # Verifica mai intai URL encoding (%xx)
    if "%" in s_clean and re.search(r"%[0-9A-Fa-f]{2}", s_clean):
        return "url"
    # Verifica daca e Hex (doar 0-9a-f/A-F si lungime para)
    if re.fullmatch(r"[0-9a-fA-F]+", s_clean) and len(s_clean) % 2 == 0:
        return "hex"
    # Verifica Base64 (doar A-Za-z0-9+/= si lungime multiplu de 4)
    if re.fullmatch(r"[A-Za-z0-9+/=]+", s_clean) and len(s_clean) % 4 == 0:
        return "base64"
    return "necunoscut"

# A3: Desface un singur strat
def desfa(s: str):
    strat = ghici_strat(s)
    try:
        if strat == "base64":
            return strat, base64.b64decode(s.strip())
        elif strat == "hex":
            return strat, bytes.fromhex(s.strip())
        elif strat == "url":
            return strat, unquote(s.strip()).encode("utf-8")
    except Exception:
        pass
    return "necunoscut", s.encode("utf-8")

# A4: Desfacere straturi multiple în buclă
def decodeaza_straturi(val: str, max_incercari: int = 8):
    istoric = []
    curent = val.strip()
    for _ in range(max_incercari):
        strat, b = desfa(curent)
        if strat == "necunoscut":
            break
        istoric.append(strat)
        
        try:
            text_rezultat = b.decode("utf-8")
        except UnicodeDecodeError:
            break
            
        if text_rezultat.startswith("FLAG{") or (citibil(b) and ghici_strat(text_rezultat) == "necunoscut"):
            return istoric, text_rezultat
        curent = text_rezultat
        
    return istoric, curent

# A5: Spargere XOR cu cheie de un singur octet (0..255)
def sparge_xor(date: bytes):
    for k in range(256):
        clar = bytes(b ^ k for b in date)
        if citibil(clar):
            return k, clar.decode("utf-8", errors="ignore")
    return None, None

# A6: Spargere hash prin dicționar
def sparge_hash(tinta_hash: str, cale_wordlist: str):
    tinta_hash = tinta_hash.strip().lower()
    lungime = len(tinta_hash)
    
    if lungime == 32:
        algo = "md5"
    elif lungime == 40:
        algo = "sha1"
    elif lungime == 64:
        algo = "sha256"
    else:
        return None, None

    try:
        with open(cale_wordlist, "r", encoding="latin1") as f:
            for linie in f:
                cuvant = linie.strip()
                h = hashlib.new(algo, cuvant.encode("utf-8")).hexdigest()
                if h == tinta_hash:
                    return cuvant, algo
    except FileNotFoundError:
        pass
    return None, algo

# A7: Interfață CLI și salvare fișă.json
def main():
    parser = argparse.ArgumentParser(description="Decoder universal si unelte de forensics.")
    parser.add_argument("intrare", nargs="?", default="probe/mesaj.txt", help="Sirul de decodat sau calea fisierului")
    parser.add_argument("--fisier", action="store_true", help="Trateaza intrarea ca cale spre un fisier")
    args = parser.parse_args()

    rezultat_final = {}

    # 1. Decodare straturi din mesaj.txt
    try:
        with open("probe/mesaj.txt", "r", encoding="utf-8") as f:
            continut = f.read().strip()
            straturi, clar = decodeaza_straturi(continut)
            rezultat_final["mesaj_straturi"] = {
                "straturi_detectate": straturi,
                "text_clar": clar
            }
            print(f"[+] Mesaj decodat din straturi: {clar}")
    except Exception as e:
        print(f"[-] Eroare mesaj.txt: {e}")

    # 2. Spargere XOR din xor.bin
    try:
        with open("probe/xor.bin", "rb") as f:
            date_xor = f.read()
            cheie, clar_xor = sparge_xor(date_xor)
            rezultat_final["xor"] = {
                "cheie_hex": hex(cheie) if cheie is not None else None,
                "text_clar": clar_xor
            }
            print(f"[+] XOR spart (cheie {hex(cheie) if cheie is not None else 'N/A'}): {clar_xor}")
    except Exception as e:
        print(f"[-] Eroare xor.bin: {e}")

    # 3. Spargere hash-uri din hashuri.txt
    try:
        parole_gasite = []
        with open("probe/hashuri.txt", "r", encoding="utf-8") as f:
            for linie in f:
                h = linie.strip()
                if h:
                    parola, algo = sparge_hash(h, "probe/wordlist.txt")
                    parole_gasite.append({"hash": h, "parola": parola, "algoritm": algo})
                    print(f"[+] Hash spart ({algo}): {h} -> {parola}")
        rezultat_final["hashuri"] = parole_gasite
    except Exception as e:
        print(f"[-] Eroare hashuri.txt: {e}")

    # Salvare fisa.json
    with open("arsenal/forensics/fisa.json", "w", encoding="utf-8") as f:
        json.dump(rezultat_final, f, indent=4, ensure_ascii=False)
    print("\n[+] Rezultatele au fost salvate cu succes in arsenal/forensics/fisa.json")

if __name__ == "__main__":
    main()