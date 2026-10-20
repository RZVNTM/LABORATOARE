# Raport Laboratorul 6 
**Student:** Crețu Răzvan 
**Grupă:** SI-264  


## Lucrarea A. ("arsenal/forensics/decode.py")

1. **Mesaj decodat din straturi succesive (`probe/mesaj.txt`):**
   - **Straturi detectate:** Base64 -> Hex -> Base64
   - **Rezultat final:** `FLAG{straturi_de_encoding}`

2. **Spargere XOR cu cheie de un octet (`probe/xor.bin`):**
   - **Cheie găsită:** `0x80` (128 în zecimal)
   - **Text clar:** `Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}`

3. **Spargere hash-uri prin dicționar (`probe/hashuri.txt`):**
   - `5f4dcc3b5aa765d61d8327deb882cf99` (MD5) -> `password`
   - `8621ffdbc5698829397d97767ac13db3` (MD5) -> `dragon`
   - `d8578edf8458ce06fbc5bb76a58c5ca4` (MD5) -> `qwerty`
   - `0d107d09f5bbe40cade3de5c71e9e9b7` (MD5) -> `letmein`
   - `d0763edaa9d9bd2a9516280e9044d885` (MD5) -> `monkey`

---

## Lucrarea B. ("forensics.py")

1. **Magic Bytes (Tipul real al fișierelor):**
   - `probe/foto.jpg` -> `jpeg` (semnătură: `\xff\xd8`)
   - `probe/ascuns.png` -> `png` (semnătură: `\x89PNG`)

2. **Strings dintr-un binar (`probe/ascuns.png`):**
   - Secvențe text identificate: `'IHDR'`, `'IDATx'`, `'IEND'`, `'secret.txtFLAG{ascuns_prin_carving}'`, `'secret.txtPK'`

3. **Metadate EXIF & GPS (`probe/foto.jpg`):**
   - **Latitudine:** `47.016666666666666` (47° 01' 0.0" N)
   - **Longitudine:** `28.8575` (28° 51' 27.0" E)
   - **Locație:** Chișinău, Republica Moldova

4. **File Carving (`probe/ascuns.png`):**
   - **Semnătură ZIP identificată la offset-ul:** `782`
   - **Fișier extras:** `secret.txt`
   - **Conținut secret:** `FLAG{ascuns_prin_carving}`

5. **Steganografie LSB (`stego.png`):**
   - **Mesaj ascuns în pixeli:** `FLAG{ascuns_in_pixeli}`
   - **Mesaj extras cu succes:** `FLAG{ascuns_in_pixeli}`