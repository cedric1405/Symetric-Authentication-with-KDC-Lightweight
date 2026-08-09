# Prototype — KDC symétrique allégé

Implémentation from scratch, en Python, d'un protocole d'authentification
centralisée à chiffrement symétrique (AES-256-GCM et HKDF), déployé en trois
conteneurs isolés. Ce dépôt accompagne le mémoire ; il fournit le code, le
déploiement et les outils de mesure.

## Organisation

    protocole/          modules de logique (testés)
      crypto.py           AES-256-GCM et HKDF (interface d'usage)
      cadrage.py          cadrage TLV sur flux TCP
      messages.py         construction/vérification des messages MSG1..MSG4
      kdc.py              base de clés JSON + service TCP du KDC
      service.py          serveur applicatif + cache anti-rejeu atomique
      client.py           orchestration de l'échange complet
    entrees/            points d'entrée des conteneurs
      lancer_kdc.py
      lancer_service.py
      lancer_client.py
    amorce/
      phase0.py           amorçage hors réseau : génère et répartit les clés
    tests_attaques.py   huit scénarios d'attaque (rejeu, usurpation, etc.)
    mesures.py          latence distribuée, décomposition, débit
    mesures_charge.py   montée en charge : capacité réelle sous N clients
    demo/
      tableau_de_bord.py       tableau de bord de visualisation en direct
      tableau_de_bord.html     page d'animation (client/KDC/service)
      attaque_rejeu_direct.py  démonstration d'attaque par rejeu en direct
    Dockerfile
    docker-compose.yml

## Prérequis

- Docker et Docker Compose, pour le déploiement conteneurisé.
- Python 3.12 et la bibliothèque `cryptography` (version 46.0.6), pour
  exécuter les tests et les mesures hors conteneur.

## Modèle de confinement des clés

Aucune clé maîtresse ne transite par le réseau. La phase 0 (amorçage) génère
la base du KDC et dépose la clé de chaque entité dans un fichier séparé. Au
déploiement, chaque conteneur ne monte, en lecture seule, que le fichier qui
le concerne : le client ne voit que K_C, le service que K_S, le KDC voit la
base complète. Le partage se fait par volume monté, hors du canal opérationnel.

## Déploiement conteneurisé

Étape 1 — amorçage (phase 0), à exécuter une seule fois. Cette commande crée
le répertoire `partage/` avec les clés réparties :

    python3 amorce/phase0.py ./partage

Vérifier que trois fichiers ont été produits, en permissions 0600 :

    ls -l partage/kdc/base.json partage/client/K_C.key partage/service/K_S.key

Étape 2 — construction et lancement des trois conteneurs :

    docker compose build
    docker compose up

Le client attend que le KDC et le service soient prêts, exécute le nombre
d'échanges fixé par `CLIENT_REPETITIONS` (100 par défaut, modifiable dans
`docker-compose.yml`), affiche le nombre de réussites et une latence
applicative, puis s'arrête. Le KDC et le service restent en écoute ; les
arrêter avec Ctrl-C ou `docker compose down`.

## Mesures de performance (chapitre 7)

Le KDC et le service doivent être en écoute (via `docker compose up -d kdc
service`, ou lancés localement, avec `TRACE_JSON` désactivé — voir plus bas).
Le script se connecte à eux et relève une distribution complète de latences,
leur décomposition par phase, et le débit soutenu. Deux méthodes, qui ne
mesurent pas tout à fait la même chose :

**Mesure A — entre conteneurs**, client exécuté dans un conteneur éphémère du
même réseau Docker que le KDC et le service (n'exige aucun port publié vers
l'hôte) :

    docker compose run --rm -e TRACE_JSON=0 \
        -v "$(pwd)/mesures.py:/app/mesures.py" client \
        python /app/mesures.py --cle /cles/K_C.key \
        --kdc kdc:9001 --service service:9002 \
        --echantillons 1000 --chauffe 50 --duree-debit 10 --histogramme

**Mesure B — depuis l'hôte**, via les ports publiés dans `docker-compose.yml`
(cas d'un client qui ne partage pas le réseau Docker du KDC/service) :

    python3 mesures.py --cle ./partage/client/K_C.key \
        --kdc 127.0.0.1:9001 --service 127.0.0.1:9002 \
        --echantillons 1000 --chauffe 50 --duree-debit 10 --histogramme

L'écart entre les deux (mesuré : latence médiane environ 2,6 fois plus élevée
en B) s'explique par la redirection de ports de Docker Desktop, traversée
uniquement en B. Les deux ont leur place dans le chapitre 7 : A comme latence
protocolaire « pure », B comme scénario d'un client externe au réseau Docker.

Pour relever la consommation CPU et mémoire de chaque conteneur pendant la
mesure, ouvrir en parallèle :

    docker stats kdc_prototype-kdc-1 kdc_prototype-service-1

Les colonnes CPU % et MEM USAGE de chaque conteneur alimentent le chapitre 7.

Remarque : les latences mesurées en boucle locale (127.0.0.1, hors conteneur)
constituent un plancher logiciel ; les mesures de référence du mémoire
doivent être relevées dans l'environnement conteneurisé (A ou B ci-dessus), où
s'ajoutent le réseau bridge et l'isolation Docker.

## Tests

Batterie des scénarios d'attaque, à exécuter hors conteneur :

    PYTHONPATH=. python3 tests_attaques.py

Les huit scénarios (rejeu direct et réseau, usurpation par adversaire interne,
ticket expiré, ticket et authentifiant altérés, concurrence sur le nonce, vol
et rejeu d'un ticket légitime) doivent tous être repoussés. Deux d'entre eux
sont étiquetés comme analogues à des attaques Kerberos recensées par Díaz
Motero et al. (2021) — voir le tableau en tête de fichier :
- **analogue Silver Ticket** (test 2) : détenteur d'une clé maîtresse valide
  qui forge un ticket sans posséder K_S ;
- **analogue Pass-the-Ticket** (test 8) : vol et rejeu d'un ticket légitime
  (sans forgerie), avec double vérification — cache de nonces, puis
  expiration du ticket sur un service qui n'a jamais vu ce nonce.

Les attaques Kerberos NON transposables (Golden Ticket, Kerberoasting,
devinette de mot de passe) ne sont volontairement pas testées : leur cible
n'existe pas dans ce protocole (pas de TGT, clés aléatoires jamais dérivées
d'un mot de passe) — leur absence de cible est la défense elle-même.

## Montée en charge (capacité réelle du déploiement)

`mesures.py` mesure un seul client séquentiel : un plancher de latence, pas
une capacité. `mesures_charge.py` lance N clients concurrents par paliers
croissants et relève, à chaque palier, le débit agrégé, la latence médiane et
p95, et le taux d'échec — pour trouver le palier où le débit cesse de croître
et où la latence décroche : c'est la capacité réelle.

Mêmes règles méthodologiques que pour `mesures.py` : mesure **entre
conteneurs** (jamais via les ports publiés), trace **inactive**.

    docker compose run --rm -e TRACE_JSON=0 \
        -v "$(pwd)/mesures_charge.py:/app/mesures_charge.py" client \
        python /app/mesures_charge.py --cle /cles/K_C.key \
        --kdc kdc:9001 --service service:9002 \
        --niveaux 1,5,10,20,50 --duree 10

Résultat obtenu le 2026-08-07 (à confirmer/affiner si repris) :

    N        débit (auth/s)   médiane (ms)     p95 (ms)   échecs (%)
    1                 165.4           5.65         8.41         0.00
    5                 246.8          17.44        41.69         0.00
    10                221.7          40.16        69.58         0.00
    20                197.4          49.72       111.06         0.00
    50                207.7          51.76      1279.80         0.00

Lecture : le débit **culmine à N=5** (≈247 auth/s) puis décline légèrement,
tandis que la latence de queue explose (p95 : 8 ms → 1280 ms de N=1 à N=50).
Aucun échec sur toute la plage : la dégradation prend la forme d'une attente,
pas d'un rejet. `docker stats` relevé en parallèle montre le CPU du service
qui **plafonne autour de 125-145 %** dès N=5 et n'augmente plus avec N — le
goulot n'est donc PAS un épuisement du CPU, mais un facteur architectural
(modèle un-fil-par-connexion, verrou global de l'interpréteur Python, ou la
file d'attente TCP limitée à 8 connexions dans `kdc.py`/`service.py`,
`socket.listen(8)`). Piste d'analyse pour le chapitre 7, pas une conclusion
établie : le code n'a pas été modifié pour confirmer laquelle de ces causes
domine.

Pour situer la saturation côté ressources, ouvrir en parallèle, sur toute la
durée du test :

    docker stats kdc_prototype-kdc-1 kdc_prototype-service-1

## Tableau de bord de visualisation en direct

Un tableau de bord local (page web servie par un petit serveur Python, sans
dépendance externe) anime en temps réel les échanges entre client, KDC et
service, ainsi qu'une démonstration d'attaque par rejeu — utile pour illustrer
le chapitre 6 ou une soutenance. Il s'appuie sur une trace JSON optionnelle
(`TRACE_JSON`) émise aux points clés du protocole.

Important : cette trace a un coût mesurable (un appel d'écriture système par
étape), qui a été chiffré à plus du double de la latence et environ 58 % de
débit en moins lors d'un essai. Elle est donc **désactivée par défaut**
(`TRACE_JSON=0`) dans `docker-compose.yml` ; les mesures de référence du
chapitre 7 doivent toujours être relevées avec la trace inactive. Ne
l'activer que pour une démonstration, jamais pendant une mesure.

Pour la démonstration, le KDC et le service doivent tourner avec la trace
active :

    TRACE_JSON=1 docker compose up -d kdc service

(PowerShell : `$env:TRACE_JSON = "1"; docker compose up -d kdc service`)

Pour reprendre des mesures de référence ensuite, redémarrer sans cette
variable pour retrouver la trace inactive :

    docker compose up -d --force-recreate kdc service

Puis, dans un autre terminal, avec le tableau de bord :

    python demo/tableau_de_bord.py

Ouvrir http://127.0.0.1:8765 dans un navigateur. Deux boutons permettent de
déclencher, sur le déploiement réel :
- un échange client unique (visible de bout en bout, MSG1 à MSG4) ;
- une démonstration d'attaque par rejeu (capture d'un MSG3 légitime, rejoué
  tel quel, repoussé par le service).

Ce tableau de bord est un outil pédagogique, pas un instrument de mesure : il
ne remplace ni `mesures.py` ni `tests_attaques.py`.

## Vérification rapide (PowerShell, Windows)

Les commandes des sections précédentes sont écrites en syntaxe Bash (Linux /
Git Bash). Sous PowerShell (l'invite par défaut sur Windows), quelques
adaptations sont nécessaires — notamment : **PowerShell continue une ligne
avec un backtick `` ` `` en fin de ligne, jamais avec `\`** (propre à Bash) ;
en cas de doute, tout mettre sur une seule ligne reste le plus sûr. Voici
l'équivalent PowerShell, prêt à copier-coller, pour vérifier soi-même
l'ensemble sans repasser par un assistant.

Se placer dans le projet et vérifier que le KDC et le service tournent :

    cd C:\Users\user\Documents\memoire\kdc_prototype
    docker compose ps

`kdc_prototype-kdc-1` et `kdc_prototype-service-1` doivent apparaître avec le
statut `Up`. Sinon :

    docker compose up -d kdc service

Tests d'attaque (les sept scénarios, hors conteneur ; `python` doit pointer
vers l'installation avec `cryptography` installé) :

    python tests_attaques.py

Attendu : `Resultat global : 9 reussis, 0 echoues`.

Mesure A — latence entre conteneurs (sans port publié), sur une seule ligne :

    docker compose run --rm -e TRACE_JSON=0 -v "${PWD}/mesures.py:/app/mesures.py" client python /app/mesures.py --cle /cles/K_C.key --kdc kdc:9001 --service service:9002 --echantillons 1000 --chauffe 50 --duree-debit 10 --histogramme

Mesure B — depuis l'hôte, via les ports publiés :

    python mesures.py --cle .\partage\client\K_C.key --kdc 127.0.0.1:9001 --service 127.0.0.1:9002 --echantillons 1000 --chauffe 50 --duree-debit 10 --histogramme

CPU / RAM pendant une mesure, dans un **second** terminal PowerShell, en
parallèle de l'une des deux commandes ci-dessus :

    docker stats kdc_prototype-kdc-1 kdc_prototype-service-1

(Ctrl+C pour arrêter l'affichage.)

Tableau de bord de visualisation (trace activée pour la démo, puis
redésactivée) :

    $env:TRACE_JSON = "1"
    docker compose up -d --force-recreate kdc service
    python demo\tableau_de_bord.py

Ouvrir ensuite http://127.0.0.1:8765. Pour revenir à des mesures propres
après la démonstration :

    Remove-Item Env:TRACE_JSON
    docker compose up -d --force-recreate kdc service

## Dépannage — Docker bloqué sur « Starting » (vpnkit)

**Symptôme** : `docker compose up` / `down` / `start` / `--force-recreate`
reste bloqué indéfiniment (parfois plusieurs minutes) sur le conteneur KDC ou
service ; `docker compose ps` affiche `Starting` sans jamais passer à `Up`.
Observé de façon récurrente sur ce poste, en particulier après un
`--force-recreate` sur kdc/service (services dont le port est publié vers
l'hôte via `ports:`).

**Cause**, vérifiable dans
`%LOCALAPPDATA%\Docker\log\host\com.docker.backend.exe.log` : une ligne
`0.0.0.0:PORT is bound in vpnkit: deferring to VM for approval check` — le
composant de redirection de ports de Docker Desktop reste coincé. Le moteur
répond par ailleurs normalement (`docker info` fonctionne, `docker ps`
aussi) ; seul le conteneur dont le port est publié reste bloqué.

Un simple clic sur « redémarrer » dans Docker Desktop ne suffit
généralement **pas** à lui seul. La procédure qui a fonctionné à chaque
occurrence, en PowerShell (pas besoin de redémarrer la machine) :

**1. Fermer Docker Desktop et tuer les processus restants :**

    taskkill /F /IM "Docker Desktop.exe" /T
    taskkill /F /IM "com.docker.backend.exe" /T
    taskkill /F /IM "com.docker.build.exe" /T
    taskkill /F /IM "docker-desktop.exe" /T
    taskkill /F /IM "docker.exe" /T

(Les erreurs « processus introuvable » sont normales : ça veut juste dire
qu'il n'y en avait pas de cette sorte-là.)

**2. Relancer Docker Desktop :**

    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

**3. Attendre que le moteur réponde** (5 à 15 secondes en général) :

    docker info

Répéter jusqu'à obtenir une réponse propre, sans `Error response from
daemon: Docker Desktop is unable to start`.

**4. Nettoyer et relancer les conteneurs :**

    cd C:\Users\user\Documents\memoire\kdc_prototype
    docker compose down --remove-orphans
    docker compose up -d kdc service

Ajouter `$env:TRACE_JSON = "1"` avant cette dernière commande si vous
relancez pour le tableau de bord plutôt que pour une mesure.

Ce blocage est quasi systématique à chaque `--force-recreate` sur kdc/service
tant qu'il n'est pas résolu autrement (mise à jour de Docker Desktop,
passage au backend Hyper-V...). Mieux vaut appliquer directement cette
procédure dès le symptôme constaté que d'attendre en espérant un déblocage
spontané.

## Paramètres du protocole

Fixés dans `protocole/messages.py` :

- fenêtre de tolérance temporelle : 300 s (± 5 min)
- durée de validité d'un ticket : 300 s
- longueur des clés : 256 bits ; nonce GCM : 96 bits
