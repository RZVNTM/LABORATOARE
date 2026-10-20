import os
import re
import zipfile
from PIL import Image
from PIL.ExifTags import TAGS

# B1. Magic bytes: tipul real al fisierului
def tip_real(cale: str) -> str:
    with open(cale, "rb") as f:
        cap = f.read(8)
    if cap.startswith(b"%PDF"):
        return "pdf"
    elif cap.startswith(b"\x89PNG"):
        return "png"
    elif cap.startswith(b"\xff\xd8"):
        return "jpeg"
    elif cap.startswith(b"PK\x03\x04"):
        return "zip/docx"
    return f"necunoscut (hex: {cap.hex()})"

# B2. Strings: secvente de text imprimabil dintr-un binar
def extrage_strings(cale: str, min_len: int = 4):
    with open(cale, "rb") as f:
        date = f.read()
    potriviri = re.findall(rb"[ -~]{" + str(min_len).encode() + rb",}", date)
    return [p.decode("utf-8", errors="ignore") for p in potriviri]

# B3. EXIF si coordonate GPS din foto.jpg
def extrage_gps(cale_foto: str):
    try:
        img = Image.open(cale_foto)
        exif = img._getexif() or {}
        date_gps = {}
        for tag_id, val in exif.items():
            nume_tag = TAGS.get(tag_id, tag_id)
            if nume_tag == "GPSInfo":
                for k in val:
                    date_gps[k] = val[k]
        
        # Conversie in grade zecimale
        lat = date_gps.get(2)
        lat_ref = date_gps.get(1)
        lon = date_gps.get(4)
        lon_ref = date_gps.get(3)
        
        if lat and lon:
            lat_dec = lat[0] + lat[1]/60.0 + lat[2]/3600.0
            if lat_ref == "S": lat_dec = -lat_dec
            
            lon_dec = lon[0] + lon[1]/60.0 + lon[2]/3600.0
            if lon_ref == "W": lon_dec = -lon_dec
            
            return lat_dec, lon_dec
    except Exception as e:
        print(f"Eroare EXIF GPS: {e}")
    return None, None

# B4. File Carving: Extragere ZIP din ascuns.png
def extrage_zip_carving(cale_png: str, cale_iesire_zip: str):
    with open(cale_png, "rb") as f:
        date = f.read()
    idx = date.find(b"PK\x03\x04")
    if idx != -1:
        with open(cale_iesire_zip, "wb") as f_out:
            f_out.write(date[idx:])
        print(f"[+] Arhiva ZIP extras de la octetul {idx} -> {cale_iesire_zip}")
        
        # Dezarhivare
        with zipfile.ZipFile(cale_iesire_zip, "r") as z:
            z.extractall("probe/extras_carving")
            for nume in z.namelist():
                continut = z.read(nume).decode("utf-8", errors="ignore")
                print(f"    Fisier extras [{nume}]: {continut.strip()}")
    else:
        print("[-] Nu s-a gasit nicio semnatura ZIP.")

# B5. Steganografie LSB: Ascunde un mesaj in pixeli
def ascunde_mesaj_lsb(cale_in: str, mesaj: bytes, cale_out: str):
    img = Image.open(cale_in).convert("RGB")
    pixels = list(img.getdata())
    
    # Adaugam terminator null
    mesaj_cu_stop = mesaj + b"\x00"
    biti = "".join(f"{b:08b}" for b in mesaj_cu_stop)
    
    noii_pixeli = []
    bit_idx = 0
    total_biti = len(biti)
    
    for r, g, b in pixels:
        canale = [r, g, b]
        for i in range(3):
            if bit_idx < total_biti:
                canale[i] = (canale[i] & ~1) | int(biti[bit_idx])
                bit_idx += 1
        noii_pixeli.append(tuple(canale))
        
    img.putdata(noii_pixeli)
    img.save(cale_out, "PNG")
    print(f"[+] Mesaj ascuns prin LSB in {cale_out}")

# B6. Steganografie LSB: Dezvaluie mesajul
def dezvaluie_mesaj_lsb(cale_stego: str) -> str:
    img = Image.open(cale_stego).convert("RGB")
    pixels = list(img.getdata())
    
    biti = []
    for r, g, b in pixels:
        biti.append(str(r & 1))
        biti.append(str(g & 1))
        biti.append(str(b & 1))
        
    octeti = []
    for i in range(0, len(biti), 8):
        b_str = "".join(biti[i:i+8])
        if len(b_str) < 8:
            break
        val = int(b_str, 2)
        if val == 0:  # Terminator mesaj
            break
        octeti.append(val)
        
    return bytes(octeti).decode("utf-8", errors="ignore")

def main():
    print("=== B1. Magic Bytes ===")
    print(f"foto.jpg -> tip real: {tip_real('probe/foto.jpg')}")
    print(f"ascuns.png -> tip real: {tip_real('probe/ascuns.png')}")

    print("\n=== B2. Strings pe binar ===")
    str_gasite = extrage_strings("probe/ascuns.png")
    print(f"Strings gasite in ascuns.png (primele 5): {str_gasite[:5]}")

    print("\n=== B3. EXIF & GPS ===")
    lat, lon = extrage_gps("probe/foto.jpg")
    print(f"Coordonate GPS extrase: Latitudine = {lat}, Longitudine = {lon}")

    print("\n=== B4. File Carving ===")
    extrage_zip_carving("probe/ascuns.png", "probe/gasit.zip")

    print("\n=== B5 & B6. Steganografie LSB ===")
    ascunde_mesaj_lsb("probe/foto.jpg", b"FLAG{ascuns_in_pixeli}", "stego.png")
    mesaj_recuperat = dezvaluie_mesaj_lsb("stego.png")
    print(f"[+] Mesaj dezvaluit din stego.png: {mesaj_recuperat}")

if __name__ == "__main__":
    main()