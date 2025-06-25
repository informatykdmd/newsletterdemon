import re

def log_stats(log_file_path):
    # Regularne wyrażenie do parsowania logów (można dostosować do formatu logów)
    log_pattern = re.compile(r'IP: (\d+\.\d+\.\d+\.\d+), Time: (.+?), Endpoint: (\S+), Method: (\S+)')

    stats = {
        'total_requests': 0,
        'requests_per_ip': {},
        'requests_per_endpoint': {},
        'requests_per_method': {}
    }

    # Odczytywanie logów
    with open(log_file_path, 'r') as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                ip, time, endpoint, method = match.groups()
                
                # Liczba zapytań
                stats['total_requests'] += 1
                
                # Liczba zapytań per IP
                if ip not in stats['requests_per_ip']:
                    stats['requests_per_ip'][ip] = 0
                stats['requests_per_ip'][ip] += 1
                
                # Liczba zapytań per endpoint
                if endpoint not in stats['requests_per_endpoint']:
                    stats['requests_per_endpoint'][endpoint] = 0
                stats['requests_per_endpoint'][endpoint] += 1
                
                # Liczba zapytań per metoda
                if method not in stats['requests_per_method']:
                    stats['requests_per_method'][method] = 0
                stats['requests_per_method'][method] += 1

    # Zwracanie statystyk
    return stats

def log_stats_dmddomy(log_file_path):
    # Dostosowane wyrażenie regularne do formatu z Node.js (IPv6 + query string w endpoint)
    log_pattern = re.compile(
        r'IP: (.*?), Time: (.*?), Endpoint: (.*?), Method: (\S+)'
    )

    stats = {
        'total_requests': 0,
        'requests_per_ip': {},
        'requests_per_endpoint': {},
        'requests_per_method': {}
    }

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                match = log_pattern.search(line)
                if match:
                    ip, time, endpoint, method = match.groups()

                    stats['total_requests'] += 1

                    stats['requests_per_ip'][ip] = stats['requests_per_ip'].get(ip, 0) + 1
                    stats['requests_per_endpoint'][endpoint] = stats['requests_per_endpoint'].get(endpoint, 0) + 1
                    stats['requests_per_method'][method] = stats['requests_per_method'].get(method, 0) + 1

    except FileNotFoundError:
        print(f"❌ Nie znaleziono pliku: {log_file_path}")

    return stats