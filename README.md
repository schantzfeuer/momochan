# Project Momochan

Satu akun untuk memainkan La Puta, The Pirate's Fortune, dan The Fish. Akun, password hash, dan progres game disimpan di SQLite pada server; browser hanya menyimpan progres sementara di memori selama game terbuka.

## Menjalankan

```powershell
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Buka `http://127.0.0.1:8000`. Database dibuat otomatis sebagai `momochan.sqlite3` di folder proyek. Set `MOMOCHAN_HTTPS_ONLY=1` saat menjalankan di balik HTTPS.