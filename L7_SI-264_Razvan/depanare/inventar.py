# inventar.py - rezumatul tintelor dintr-un fisier JSON
# Reparat si functional
import argparse
import json


def incarca(cale):
    """Citeste lista de tinte din fisierul JSON."""
    with open(cale) as f:
        return json.load(f)


def port_valid(text):
    """Intoarce portul ca int, sau None daca nu e un numar."""
    try:
        return int(text)
    except ValueError:
        return None


def pe_servicii(tinte):
    """Dict: serviciu -> lista de porturi."""
    grupe = {}
    for t in tinte:
        serviciu = t.get("serviciu", "necunoscut")
        port = port_valid(t["port"])
        if port is None:
            print("sar peste", t.get("gazda", t.get("ip", "necunoscut")), ": port invalid", t["port"])
            continue

        grupe.setdefault(serviciu, []).append(port)
    return grupe


def peste_prag(tinte, prag):
    """Lista gazdelor cu un port mai mare decat pragul."""
    rezultat = []
    for t in tinte:
        port = port_valid(t["port"])
        if port is not None and port > prag:
            rezultat.append(t.get("gazda", t.get("ip")))
    return rezultat


def main():
    p = argparse.ArgumentParser()
    p.add_argument("fisier")
    p.add_argument("--prag", type=int, default=1024)
    a = p.parse_args()

    tinte = incarca(a.fisier)
    print("Tinte citite: " + str(len(tinte)))

    grupe = pe_servicii(tinte)
    for serviciu, porturi in grupe.items():
        print(f"{serviciu}: {porturi}")

    mari = peste_prag(tinte, a.prag)
    print(f"Peste {a.prag}: {mari}")

    with open("raport_inventar.json", "w") as f:
        json.dump({"servicii": grupe, "peste_prag": mari}, f, indent=2)
    print("Raport salvat in raport_inventar.json")


if __name__ == "__main__":
    main()