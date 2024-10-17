from re import compile as recompile
from sys import exit as sysexit, argv
from os import mkdir, path, access, W_OK
from enum import Enum
from datetime import datetime
from subprocess import call, DEVNULL, STDOUT
from socket import gethostbyname, gaierror, AddressFamily
from psutil import net_if_addrs

TEMP_DIR = "/tmp"
LOG_DIR = f"{TEMP_DIR}/network_tp3"
LOG_FILE = f"{LOG_DIR}/network.log"

def create_log_dir() -> bool:
    """Creates LOG_DIR and checks if LOG_FILE is writable"""
    if not path.exists(LOG_DIR):
        try:
            mkdir(LOG_DIR)
        except Exception:
            print(f"Could not create log directory {LOG_DIR}.")
            sysexit(2)

    if not access(LOG_DIR, W_OK):
        print(f"Can't write to log file {LOG_FILE}.")
        sysexit(3)

    return True


class LogLevel(Enum):
    """Simple log level enums"""

    INFO = 1
    ERROR = 2


def log(msg: str, log_level: LogLevel) -> True:
    """Writes given msg to LOG_FILE adding a timestamp"""
    # on récupère un timestamp au bon format pour la ligne de log
    log_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # construction de la ligne de log
    log_line = f"{log_timestamp} [{log_level.name}] {msg}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

    return True


def ping(ip_address: str) -> bool:
    """Ping a given IPv4 address"""

    # exécution de la commande ping en supprimant toute sortie
    return_code = call(["ping", "-c", "4", ip_address], stdout=DEVNULL, stderr=STDOUT)

    # test du code retour du ping
    # si c'est 0, le ping a fonctionné et on retourne True
    # sinon on retourne False
    return bool(return_code == 0)


def ping_subcommand() -> bool:
    """Handle ping subcommand"""

    if len(argv) < 3:
        print("You must input an IP address as an argument.")
        log("Command ping called without argument.", LogLevel.ERROR)
        sysexit(11)

    # on ré-affecte l'argument passé dans une variable avec un nom approprié
    ip_address = argv[2]

    # on vérifie que l'argument saisi est au bon format (adresse IPv4)
    ip_address_regex = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
    ip_address_regex = recompile(ip_address_regex)
    if not ip_address_regex.match(ip_address):
        print(f"{ip_address} is not a valid IP address")
        log(f"Command ping called with bad arguments : {ip_address}.", LogLevel.ERROR)
        sysexit(12)

    if ping(ip_address):
        print("UP !")
    else:
        print("DOWN !")

    log(f"Command ping called successfully with argument {ip_address}.", LogLevel.INFO)
    return True


def lookup(name: str) -> str:
    """Issue a DNS lookup to a given name"""

    try:
        ip_address = gethostbyname(name)
        return ip_address
    except gaierror:
        # on catch l'erreur quand le nom de domaine n'est associé à aucune IP
        # comme ça, on peut retourner une string vide
        return ""


def lookup_subcommand() -> bool:
    """Handle lookup subcommand"""

    if len(argv) < 3:
        print("You must input a domain name address as an argument.")
        log("Command lookup called without argument.", LogLevel.ERROR)
        sysexit(13)

    # on ré-affecte l'argument passé dans une variable avec un nom approprié
    domain_name = argv[2]

    # vérification que le nom de domaine saisi est au bon format (nom de domaine)
    domain_name_regex = r"^([a-zA-Z0-9]{1,128}\.){1,16}[a-z]{2,5}$"
    domain_name_regex = recompile(domain_name_regex)
    if not domain_name_regex.match(domain_name):
        print(f"{domain_name} is not a valid domain name")
        log(
            f"Command lookup called with bad arguments : {domain_name}.", LogLevel.ERROR
        )
        sysexit(14)

    # appel de la fonction au dessus pour effectuer le lookup DNS
    ip_address = lookup(domain_name)

    if ip_address == "":
        print(f"No IP address found for domain {domain_name}")
    else:
        print(ip_address)

    log(
        f"Command lookup called successfully with argument {domain_name}.",
        LogLevel.INFO,
    )
    return True


def get_ip() -> (str, int):
    """Retrieve informations about the current WiFi interface"""
    nics_data = net_if_addrs()

    # initialisation de quelques variables
    wifi_nic = ""
    wifi_ip_address = ""
    wifi_ip_netmask = ""

    # itération sur la liste des cartes réseau
    for nic_name in nics_data:
        # on cherche la carte WiFi
        if "Wi-Fi" in nic_name or "wl" in nic_name:
            # une fois trouvée, on stocke son nom complet dans une variable
            wifi_nic = nic_name

    # itération sur les données de la carte WiFi
    for data in nics_data[wifi_nic]:
        # on cherche les données IPv4
        if data.family == AddressFamily.AF_INET:
            wifi_ip_address = data.address
            wifi_ip_netmask = data.netmask

    binary_mask = ""
    # conversion du masque en binaire, puis cast en string
    for byte in wifi_ip_netmask.split("."):
        binary_mask += str(bin(int(byte))).replace("0b", "")

    # pour déterminer le masque en format CIDR, on compte le nombre de 1 dans le masque
    wifi_ip_cidr_netmask = binary_mask.count("1")

    # simple calcul pour déterminer le nombre d'adresses IP dispos dans ce réseau
    available_addresses_count = pow(2, 32 - wifi_ip_cidr_netmask)

    return (f"{wifi_ip_address}/{wifi_ip_cidr_netmask}", available_addresses_count)


def get_ip_subcommand() -> bool:
    """Handle get_ip subcommand"""
    ip_address, available_addresses = get_ip()

    print(f"{ip_address}\n{available_addresses} addresses")
    log("Command get_ip called successfully.", LogLevel.INFO)

    return True


if __name__ == "__main__":
    create_log_dir()

    if len(argv) < 2:
        print("You must input a subcommand as argument : ping, lookup, get_ip.")
        log("Called without any subcommand.", LogLevel.ERROR)
        sysexit(4)

    # déclaration d'une liste qui contient la liste des sous-commandes autorisées
    AVAILABLE_SUBCOMMANDS = ["ping", "lookup", "get_ip"]

    # récupération de la sous-commande demandée
    SUBCOMMAND = argv[1]

    # on teste si la sous-commande demandée est dans la liste AVAILABLE_SUBCOMMANDS
    if SUBCOMMAND not in AVAILABLE_SUBCOMMANDS:
        print(
            f"""{SUBCOMMAND} is not a valid command. Déso.
Available : {', '.join(AVAILABLE_SUBCOMMANDS)}."""
        )
        log(f"Called with a bad subcommand : {SUBCOMMAND}.", LogLevel.ERROR)
        sysexit(5)

    # on ne met pas de cas général à ce match/case car on a testé
    # la valeur de SUBCOMMAND au dessus
    match SUBCOMMAND:
        case "ping":
            ping_subcommand()

        case "lookup":
            lookup_subcommand()

        case "get_ip":
            get_ip_subcommand()

    # si on arrive en fin de script, on quitte proprement avec un code retour 0
    # pour rappel : une commande qui retourne 0, c'est qu'elle indique que tout s'est bien passé
    sysexit(0)
