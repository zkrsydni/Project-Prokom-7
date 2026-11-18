
import os
from dataclasses import dataclass
from typing import Optional
from google import genai

@dataclass
class NetworkScanData:
    ssid: str
    bssid: str
    rssi: int
    channel: int
    frequency_mhz: float
    security_type: str

@dataclass
class AIRecommendation:
    ssid: str
    signal_status: str
    security_assessment: str
    recommended_action: str
    channel_optimization_tip: Optional[str] = None

class AIAdvisor:
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Inisialisasi client GenAI
        self.client = genai.Client(api_key=self.api_key) if api_key else None

    def evaluate_signal(self, rssi: int) -> str:
        if rssi >= -60:
            return "Sangat Baik (Sinyal Kuat)"
        elif -75 <= rssi < -60:
            return "Sedang (Sinyal Cukup Baik)"
        else:
            return "Buruk (Sinyal Lemah / Berpotensi Instabil)"

    def analyze_network(self, scan_data: NetworkScanData) -> AIRecommendation:
        signal_status = self.evaluate_signal(scan_data.rssi)
        
        if scan_data.security_type.upper() in ["OPEN", "NONE"]:
            sec_assessment = "BAHAYA: Jaringan terbuka tanpa enkripsi."
            sec_action = "Hindari bertransaksi sensitif atau gunakan VPN terenkripsi."
        elif "WEP" in scan_data.security_type.upper():
            sec_assessment = "RENTAN: Enkripsi WEP sudah usang dan mudah diretas."
            sec_action = "Tingkatkan protokol keamanan router ke WPA2 atau WPA3."
        else:
            sec_assessment = f"AMAN: Menggunakan protokol {scan_data.security_type}."
            sec_action = "Jaringan relatif aman untuk penggunaan standar."

        channel_tip = "Gunakan channel non-overlapping jika ada interferensi."

        return AIRecommendation(
            ssid=scan_data.ssid,
            signal_status=signal_status,
            security_assessment=sec_assessment,
            recommended_action=sec_action,
            channel_optimization_tip=channel_tip
        )

    # --- TUGAS NOMOR 32: FALLBACK RESPONSE OTOMATIS ---
    def _generate_fallback_advice(self, qos_data: dict, security_data: dict, alasan: str = "") -> str:
        download = qos_data.get('download_mbps', 0)
        ping = qos_data.get('ping_ms', 999)
        sec_score = security_data.get('score', 0)
        sec_category = security_data.get('category', 'Tidak Diketahui')

        # Menyusun Paragraf 1 (Evaluasi Kecepatan & Latensi)
        if download >= 10.0 and ping <= 50.0:
            p1 = (
                f"Dengan kecepatan unduh {download} Mbps dan latensi (ping) {ping} ms, "
                "koneksi jaringan ini tergolong stabil dan responsif. Performa tersebut sangat memadai "
                "untuk melakukan panggilan video (video call) berkualitas tinggi maupun bermain game online tanpa hambatan berarti."
            )
        elif download >= 5.0 and ping <= 100.0:
            p1 = (
                f"Kecepatan unduh sebesar {download} Mbps dengan ping {ping} ms sudah cukup layak "
                "untuk kebutuhan rapat daring atau panggilan video standar. Namun, untuk game online kompetitif, "
                "Anda mungkin sesekali merasakan sedikit jeda (lag)."
            )
        else:
            p1 = (
                f"Kecepatan unduh saat ini hanya {download} Mbps dengan latensi tinggi ({ping} ms). "
                "Koneksi ini kurang disarankan untuk panggilan video maupun game online karena berisiko tinggi mengalami putus-putus atau lag."
            )

        # Menyusun Paragraf 2 (Evaluasi Keamanan M-Banking)
        if sec_score >= 75 and "aman" in sec_category.lower():
            p2 = (
                f"Dari sisi keamanan, jaringan ini berstatus '{sec_category}' (skor {sec_score}/100). "
                "Koneksi terenkripsi dengan baik sehingga relatif aman digunakan untuk mengakses layanan perbankan digital (m-banking) maupun transaksi sensitif lainnya."
            )
        else:
            p2 = (
                f"Peringatan keamanan: jaringan ini terdeteksi berstatus '{sec_category}' (skor {sec_score}/100). "
                "Sangat tidak disarankan membuka aplikasi m-banking atau memasukkan kata sandi penting di jaringan ini kecuali Anda menggunakan perlindungan VPN terenkripsi."
            )

        catatan_sistem = f"[Mode Offline / Fallback Otomatis Aktif{f': {alasan}' if alasan else ''}]"
        return f"{p1}\n\n{p2}\n\n{catatan_sistem}"

    # --- TUGAS MINGGU 2 (TASK 4.2) + INTEGRASI FALLBACK (TUGAS 32) ---
    def generate_wifi_advice(self, qos_data: dict, security_data: dict) -> str:
        # Jika API Key tidak ada, langsung jalankan fallback
        if not self.api_key or not self.client:
            return self._generate_fallback_advice(qos_data, security_data, "API Key belum dikonfigurasi")

        download = qos_data.get('download_mbps', 0)
        ping = qos_data.get('ping_ms', 0)
        sec_category = security_data.get('category', 'Tidak Diketahui')

        prompt = f"""
        Anda adalah asisten cerdas penganalisis jaringan WiFi.
        Data jaringan saat ini: Kecepatan Download {download} Mbps, Latensi (Ping) {ping} ms, dan Status Keamanan: {sec_category}.
        
        Berikan saran singkat 2 paragraf dalam bahasa Indonesia. 
        Paragraf 1: Beritahu apakah kecepatan ini cukup lancar untuk video call atau main game online.
        Paragraf 2: Beritahu apakah aman membuka m-banking berdasarkan status keamanannya.
        """

        try:
            response = self.client.models.generate_content(
                model='gemini-3.8-flash',
                contents=prompt
            )
            # Pastikan respons teks tidak kosong
            if response and response.text:
                return response.text
            return self._generate_fallback_advice(qos_data, security_data, "Respons LLM kosong")
            
        except Exception as e:
            pesan_error = str(e)
            if "429" in pesan_error or "RESOURCE_EXHAUSTED" in pesan_error:
                alasan = "Kuota API Gemini habis"
            elif "503" in pesan_error or "UNAVAILABLE" in pesan_error:
                alasan = "Server Gemini sedang penuh (503)"
            else:
                alasan = "Koneksi ke server LLM terputus"
                
            return self._generate_fallback_advice(qos_data, security_data, alasan)

    # --- TUGAS NOMOR 31: SISTEM REKOMENDASI LABEL KELAYAKAN AKTIVITAS OTOMATIS ---
    def generate_activity_labels(self, qos_data: dict, security_data: dict) -> dict:
        download = qos_data.get('download_mbps', 0)
        upload = qos_data.get('upload_mbps', 0)
        ping = qos_data.get('ping_ms', 999)
        sec_score = security_data.get('score', 0)
        sec_category = security_data.get('category', 'Rawan').lower()

        labels = []
        status_utama = ""

        # 1. Evaluasi Kelayakan Transaksi Keuangan (M-Banking / E-Wallet)
        if sec_score >= 75 and "aman" in sec_category:
            labels.append("✅ Aman untuk M-Banking & Transaksi Sensitif")
        else:
            labels.append("❌ DILARANG untuk M-Banking (Risiko Keamanan)")

        # 2. Evaluasi Kelayakan Gaming Online & Video Call (Zoom/Meet)
        if download >= 10.0 and upload >= 3.0 and ping <= 50.0:
            labels.append("✅ Lancar untuk Video Call HD & Gaming Online")
        elif download >= 5.0 and ping <= 100.0:
            labels.append("⚠️ Cukup untuk Video Call Standar (Kurang Ideal untuk Gaming)")
        else:
            labels.append("❌ Tidak Disarankan untuk Video Call / Gaming (Lag Tinggi)")

        # 3. Evaluasi Kelayakan Streaming & Browsing
        if download >= 15.0:
            labels.append("✅ Lancar Streaming Video 4K / Full HD")
        elif download >= 3.0:
            labels.append("✅ Cukup untuk Streaming 720p & Media Sosial")
        elif download > 0:
            labels.append("⚠️ Hanya Cocok untuk Chatting & Browsing Ringan")
        else:
            labels.append("❌ Tidak Ada Koneksi Internet")

        # 4. Penentuan Badge/Status Utama Jaringan (Untuk ditampilkan di UI Zakkiyah)
        if sec_score < 50:
            status_utama = "JARINGAN BERISIKO (Gunakan VPN)"
        elif download >= 15.0 and ping <= 50.0:
            status_utama = "SANGAT DIREKOMENDASIKAN (Performa Tinggi)"
        elif download >= 5.0:
            status_utama = "LAYAK DIGUNAKAN (Standar)"
        else:
            status_utama = "PERFORMA LAMBAT"

        return {
            "status_utama": status_utama,
            "daftar_label": labels
        }

# --- AREA UJI COBA ---
if __name__ == "__main__":
    
    AI_API_KEY = "AQ.Ab8RN6LMFCV5SGrgjcUr8ChNgQD_2qK7hepJvZtOWCqfWmWosA"
    advisor = AIAdvisor(api_key=AI_API_KEY)
    
    # 1. Simulasi data dari Azka (Network Engineer)
    dummy_qos = {
        'download_mbps': 15.5,
        'upload_mbps': 5.2,
        'ping_ms': 45.0
    }
    
    # 2. Simulasi data dari Brava (Cybersecurity)
    dummy_security = {
        'score': 40,
        'category': 'Rawan',
        'findings': ['Captive portal terdeteksi']
    }
    
    print("Meminta saran pintar dari Gemini API (dengan Fallback Otomatis)...\n")
    saran_ai = advisor.generate_wifi_advice(dummy_qos, dummy_security)
    
    print("=== HASIL SARAN AI ===")
    print(saran_ai)

    print("\n=== HASIL LABEL KELAYAKAN AKTIVITAS OTOMATIS ===")
    hasil_label = advisor.generate_activity_labels(dummy_qos, dummy_security)
    print(f"Status Utama : {hasil_label['status_utama']}")
    print("Rincian Aktivitas:")
    for label in hasil_label['daftar_label']:
        print(f" - {label}")
