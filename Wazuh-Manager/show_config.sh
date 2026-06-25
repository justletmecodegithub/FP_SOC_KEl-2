#!/usr/bin/env bash
# ============================================================================
# show_config.sh - Tampilkan SEMUA konfigurasi yang KAMI ubah untuk proyek ini.
# Jalankan di VM-WAZUH-MANAGER. Buat presentasi ke dosen.
#   Pakai:  sudo bash show_config.sh
#   Simpan: sudo bash show_config.sh > konfigurasi_kami.txt
# ============================================================================
sep(){ echo; echo "============================================================"; echo " $1"; echo "============================================================"; }

sep "1. CUSTOM RULES (deteksi DoS + zona abu-abu untuk ML)"
echo "File: /var/ossec/etc/rules/local_rules.xml"
echo "------------------------------------------------------------"
sudo cat /var/ossec/etc/rules/local_rules.xml

sep "2. CUSTOM DECODER (membaca penanda keputusan ML)"
echo "File: /var/ossec/etc/decoders/local_decoder.xml"
echo "------------------------------------------------------------"
sudo cat /var/ossec/etc/decoders/local_decoder.xml

sep "3. INTEGRASI ML — pemanggil API model"
echo "File: /var/ossec/integrations/custom-ml-predict.py"
echo "------------------------------------------------------------"
sudo cat /var/ossec/integrations/custom-ml-predict.py

sep "4. KONFIGURASI WAZUH — blok yang kami tambahkan di ossec.conf"
echo "File: /var/ossec/etc/ossec.conf  (hanya bagian relevan)"
echo "------------------------------------------------------------"
echo ">>> Blok INTEGRATION (kirim alert ke ML):"
sudo grep -n -B1 -A4 'custom-ml-predict' /var/ossec/etc/ossec.conf
echo
echo ">>> Blok ACTIVE-RESPONSE (auto-block dari keputusan AI):"
sudo grep -n -A6 '<active-response>' /var/ossec/etc/ossec.conf
echo
echo ">>> LOCALFILE (Wazuh memantau log keputusan block):"
sudo grep -n -A3 'ml-block.log' /var/ossec/etc/ossec.conf

sep "5. RINGKASAN ALUR (Human-AI + SOAR)"
cat <<'TXT'
  Serangan web
    -> Rule Wazuh (31101 / 100112 / 100113) terpicu
    -> Integrasi custom-ml-predict.py kirim alert ke ML API
    -> Model Random Forest klasifikasi: TP (serangan) / FP (false alarm)
    -> Jika TP & confidence >= 0.85 -> tulis ML_BLOCK ke log
    -> Decoder 'ml-block' + Rule 100200 membacanya
    -> Active Response (firewall-drop) blokir IP di Target-Web, timeout 120s
    -> Auto-unblock setelah 2 menit
TXT
echo
echo "Selesai. (Konfigurasi sisi ML: ~/ml-api/main.py & monitor.py ada di VM-ML)"
