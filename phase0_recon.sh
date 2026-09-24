#!/usr/bin/env bash
# TP2 - Incident Response - PHASE 0 : reconnaissance de la VM Wazuh
# LECTURE SEULE : ce script ne modifie rien sur le système.
# Seule écriture : ajout des résultats dans ~/tp2_incident_response_notes.txt
#
# Usage (sur la VM Wazuh, en tant que wazuh-user) :
#   bash phase0_recon.sh

NOTES="$HOME/tp2_incident_response_notes.txt"

run() {
    echo "----- COMMANDE : $* -----"
    "$@" 2>&1
    echo "----- code retour : $? -----"
    echo
}

{
    echo "=================================================="
    echo "PHASE 0 - RECONNAISSANCE DE LA VM"
    echo "Date (locale) : $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Date (UTC)    : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Opérateur     : $(whoami)"
    echo "=================================================="
    echo

    run cat /etc/os-release
    run uname -a
    run hostname
    run ip -brief addr
    run ip route
    run sudo systemctl status wazuh-manager --no-pager
    run sudo /var/ossec/bin/wazuh-control info
    run ls -l /var/log/secure
    run ls -l /var/ossec/etc/ossec.conf
    run ls -l /var/ossec/logs/alerts/alerts.log
    run ls -l /var/ossec/logs/active-responses.log
    run command -v iptables
    run sudo iptables -L -n --line-numbers
    run ls -l /etc/hosts.deny
    run sudo systemctl is-active sshd
    run ls -l /usr/bin/find
} | tee -a "$NOTES"

echo
echo ">> Résultats ajoutés à : $NOTES"
echo ">> Copiez-collez la sortie ci-dessus dans la conversation pour l'analyse."
