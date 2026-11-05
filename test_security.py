"""test_security.py - Task 3.5: pengujian skenario modul keamanan."""
from modules import security_test as st

import ssl
from unittest.mock import patch

hasil = []



def cek(nama, kondisi):
    print(("LULUS  " if kondisi else "GAGAL  ") + nama)
    hasil.append(bool(kondisi))


print("== 1. Skenario simulasi ==")
for nama, skor, kategori in [("aman", 100, "Aman"), ("rawan", 60, "Rawan"), ("bahaya", 0, "Bahaya")]:
    r = st.audit_wifi(simulate=nama)
    cek(f"{nama}: skor {r['score']}, kategori {r['category']}",
        r["score"] == skor and r["category"] == kategori)

print("\n== 2. Batas kategori ==")
batas = [
    ("skor 80 -> Aman",  {"no_hsts": True, "no_csp": True, "no_xfo": True}, 80, "Aman"),
    ("skor 75 -> Rawan", {"no_hsts": True, "no_csp": True, "no_xfo": True, "no_xcto": True}, 75, "Rawan"),
    ("skor 50 -> Rawan", {"ssl_invalid": True, "no_hsts": True}, 50, "Rawan"),
    ("skor 45 -> Bahaya", {"ssl_invalid": True, "no_hsts": True, "no_csp": True}, 45, "Bahaya"),
    ("pemeriksaan gagal -> 90", {"check_failed": True}, 90, "Aman"),
]
for nama, obs, skor, kategori in batas:
    r = st.calculate_security_score(obs)
    cek(nama, r["score"] == skor and r["category"] == kategori)

print("\n== 3. Format output (kontrak data) ==")
r = st.audit_wifi(simulate="rawan")
cek("key score/category/findings ada", set(r) == {"score", "category", "findings"})
cek("score bertipe int 0-100", isinstance(r["score"], int) and 0 <= r["score"] <= 100)
cek("findings berupa list string", isinstance(r["findings"], list) and all(isinstance(x, str) for x in r["findings"]))

print("\n== 4. Sertifikat asli (butuh internet) ==")
for nama, host, harapan in [
    ("google valid", "www.google.com", {"ssl_invalid": False, "ssl_expired": False}),
    ("self-signed", "self-signed.badssl.com", {"ssl_invalid": True}),
    ("kedaluwarsa", "expired.badssl.com", {"ssl_expired": True}),
    ("hostname salah", "wrong.host.badssl.com", {"ssl_invalid": True}),
]:
    r = st.check_ssl(host)
    if r["check_failed"]:
        print(f"DILEWATI  {nama} (koneksi ke {host} gagal atau diblokir jaringan)")
        continue
    cek(f"{nama}", all(r[k] == v for k, v in harapan.items()))

print("\n== 5. Logika expired (tanpa internet, error disimulasikan) ==")
err = ssl.SSLCertVerificationError(1, "certificate has expired")
err.verify_code = 10
with patch.object(st.socket, "create_connection", side_effect=err):
    r = st.check_ssl("contoh.test")
cek("kode 10 -> ssl_expired", r["ssl_expired"] and not r["ssl_invalid"])
print(f"\n{sum(hasil)} dari {len(hasil)} tes lulus")
