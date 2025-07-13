# Course Scheduling System

Sistem penjadwalan mata kuliah menggunakan Flask, Neo4j, dan algoritma Graph Coloring.

## Fitur

### User Management (CRUD)
- **Admin**: Mengelola semua user, mata kuliah, dan penjadwalan
- **Dosen**: Melihat mata kuliah yang diajar
- **Mahasiswa**: Mendaftar mata kuliah dan melihat jadwal
  
### Graph Coloring untuk Penjadwalan
- **Greedy Algorithm**: Algoritma pewarnaan graf yang cepat dan sederhana. Cocok sebagai baseline, namun hasilnya sangat bergantung pada urutan simpul yang diproses.
- **Welsh-Powell Algorithm**: Algoritma pewarnaan graf heuristik yang mengurutkan simpul berdasarkan derajat tertinggi terlebih dahulu, sehingga lebih optimal dalam meminimalkan jumlah warna (slot waktu).
- **Conflict Detection**: Sistem secara otomatis mendeteksi konflik antar mata kuliah berdasarkan mahasiswa yang mengambil keduanya, kemudian membentuk edge antar mata kuliah di dalam graf.

### Fitur Utama
- Dashboard berbeda untuk setiap role
- Enrollment system untuk mahasiswa
- Automatic schedule generation
- Conflict visualization
- Time slot management

## Requirements

### Software
- Python 3.8+
- Neo4j Database 4.4+
- Modern web browser

### Python Dependencies
```
Flask==2.3.3
neo4j==5.13.0
Werkzeug==2.3.7
```
