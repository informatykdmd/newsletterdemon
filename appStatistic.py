# log_stats.py
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
