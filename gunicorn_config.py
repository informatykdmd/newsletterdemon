import multiprocessing

# Podstawowe konfiguracje
bind = "185.201.114.123:8000"  # Adres IP i port na którym Gunicorn będzie nasłuchiwał
workers = 1 # multiprocessing.cpu_count() * 2 + 1  # Zalecana liczba procesów pracowniczych
accesslog = "-"  # Logowanie dostępu; "-" oznacza stdout
errorlog = "-"  # Logowanie błędów; "-" oznacza stderr
worker_class = 'sync'  # Typ klasy pracownika (np. sync, gevent, uvicorn.workers.UvicornWorker)

# Zaawansowane konfiguracje
timeout = 30  # Maksymalny czas oczekiwania na odpowiedź pracownika (w sekundach)
keepalive = 2  # Czas, po którym połączenie jest zamykane, jeśli nie było aktywności (w sekundach)
