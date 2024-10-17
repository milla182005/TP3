#!/usr/bin/env python
""" Prints the IPv4 address and mask of the WiFi interface.
    Also prints the total available IPv4 addresses in the current LAN """

from socket import AddressFamily
from psutil import net_if_addrs

if __name__ == "__main__":
    # récupération de la list des cartes réseau et leurs infos
    nics_data = net_if_addrs()

    # on initialise des variables pour la suite
    wifi_nic = ""
    wifi_ip_address = ""
    wifi_ip_netmask = ""

    # itération sur toutes les cartes réseau
    for nic_name in nics_data:
        # pour chaque réseau, on teste son nom pour savoir si on a la carte WiFi
        if "Wi-Fi" in nic_name or "wl" in nic_name:
            # on stocke le nom de la carte WiFi une fois trouvée
            wifi_nic = nic_name

    # itération sur les données de la carte WiFi
    for data in nics_data[wifi_nic]:
        # si on trouve des infos IPv4
        if data.family == AddressFamily.AF_INET:
            # on stocke l'adresse IP et le masque
            wifi_ip_address = data.address
            wifi_ip_netmask = data.netmask

    binary_mask = ""
    # itération sur chaque octet du masque trouvé
    for byte in wifi_ip_netmask.split("."):
        # pour chaque octet, on le convertit en binaire
        # puis on le cast en string, et on le concatène à binary_mask
        binary_mask += str(bin(int(byte))).replace("0b", "")

    # on compte le nombre de 1 présent dans le masque sous forme binaire
    wifi_ip_cidr_netmask = binary_mask.count("1")
    # calcul du nombre d'adresses : 2^(32-mask)
    available_addresses_count = pow(2, 32 - wifi_ip_cidr_netmask)

    print(
        f"{wifi_ip_address}/{wifi_ip_cidr_netmask}\n{available_addresses_count} addresses"
    )
