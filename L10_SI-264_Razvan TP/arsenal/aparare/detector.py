import argparse
import json
from collections import Counter
from arsenal.aparare.parse_auth import citeste_esecuri

def suspecti(counts, prag=10):
   
    if prag < 1:
        raise ValueError(f"prag invalid: {prag} (cel putin 1)")
    
    rezultate = [(ip, n) for ip, n in counts.items() if n >= prag]
    rezultate.sort(key=lambda x: x[1], reverse=True)
    return rezultate

def main():
    p = argparse.ArgumentParser(description="Detector de atacuri Brute Force")
    p.add_argument("log", help="Calea către fișierul auth.log")
    p.add_argument("--prag", type=int, default=10, help="Pragul minim de eșecuri (implicit 10)")
    p.add_argument("--json", action="store_true", help="Generare raport în format JSON")
    a = p.parse_args()

    esecuri = citeste_esecuri(a.log)
    counts = Counter(e["ip"] for e in esecuri)
    sus = suspecti(counts, a.prag)

    if a.json:
        raport = {
            "esecuri": len(esecuri),
            "pe_ip": dict(counts),
            "suspecti": [{"ip": ip, "incercari": n} for ip, n in sus]
        }
        print(json.dumps(raport, indent=2))
    else:
        print(f"Esecuri de autentificare: {len(esecuri)}")
        for ip, n in counts.most_common():
            print(f"  {ip}: {n}")
        print(f"Suspecti (prag {a.prag}):")
        for ip, n in sus:
            print(f"  {ip}  ({n} incercari)  BRUTE FORCE")

if __name__ == "__main__":
    main()