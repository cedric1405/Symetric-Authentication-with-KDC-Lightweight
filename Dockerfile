# Image commune aux trois entites du protocole (KDC, service, client).
# Le code est identique ; seule la commande de lancement, fixee par
# docker-compose, distingue les conteneurs.

FROM python:3.12-slim

# Sans cela, Python met en tampon sa sortie standard des qu'elle n'est pas un
# terminal (le cas ici) : les print() des points d'entree n'apparaitraient
# dans `docker compose up` / `docker compose logs` qu'a la fin du programme,
# voire jamais s'il ne se termine pas. Effet uniquement sur la visibilite des
# journaux, jamais sur le comportement du protocole.
ENV PYTHONUNBUFFERED=1

# Bibliotheque cryptographique : fournit AES-256-GCM et HKDF.
RUN pip install --no-cache-dir cryptography==46.0.6

WORKDIR /app

# Le paquet du protocole et les points d'entree.
COPY protocole/ /app/protocole/
COPY entrees/ /app/entrees/

# Aucune commande par defaut : docker-compose precise le point d'entree de
# chaque conteneur.
