# Note de contexte — reprise du prototype (mise à jour)

Ce fichier remet un assistant (Claude Code sur l'éditeur) dans le bain du projet.
Il décrit le cadre, ce qui est acquis, les évolutions récentes, et les deux
chantiers ouverts. Objectif : collaborer sans contredire des décisions déjà
tranchées et défendues dans le mémoire.

## Nature du travail

Prototype d'un mémoire de Master 2 en sécurité informatique (Université de
Yaoundé I). Implémentation *from scratch*, en Python, d'un protocole
d'authentification centralisée à chiffrement symétrique dans un réseau LAN,
sans infrastructure propriétaire. Inspiré de Kerberos mais délibérément
simplifié. Sert les chapitres 6 (implémentation) et 7 (résultats).

Le travail attendu ici est **technique** (code, déploiement, mesures). La
rédaction académique se poursuit dans une autre interface qui détient
l'historique complet du mémoire.

## Règle absolue héritée du mémoire

**Zéro invention.** Toute affirmation qui remontera dans le mémoire doit
correspondre à ce que le code fait réellement et à ce que les mesures montrent.
Les limites s'assument, elles ne se masquent pas. Un obstacle rencontré et
résolu a sa place dans le récit du chapitre 6.

## Décisions de conception ARRÊTÉES — ne pas rouvrir

- Deux phases, PAS de TGT réutilisable. Conséquence assumée : pas de SSO.
- Aucune revendication Zero Trust. Ne pas reformuler en ces termes.
- Clés maîtresses générées ALÉATOIREMENT par le KDC, jamais dérivées de mots de
  passe (neutralise Kerberoasting et devinette — argument de sécurité central).
- Base de clés du KDC en JSON, permissions système. Concentration des secrets
  assumée comme limite, pas résolue.
- Anti-rejeu : cache de nonces en mémoire, vérification et enregistrement
  ATOMIQUES (verrou). L'atomicité est une condition de la propriété.
- Sous-clés unidirectionnelles K_CS et K_SC dérivées par HKDF (identités + sens
  en contexte). Ne pas fusionner en une clé bidirectionnelle.
- AES-256-GCM ; étiquettes de cadrage (type, sens) en données associées (AAD).
- Confidentialité persistante et anonymat : HORS objectifs, assumés comme
  limites (perspectives, chap. 8). Ne pas tenter de les « ajouter ».
- Transport : TCP + cadrage TLV à deux niveaux. Longueurs 2 octets, big-endian.
- Distribution des clés HORS BANDE, par volume monté en lecture seule — JAMAIS
  par variable d'environnement, JAMAIS sur le réseau opérationnel.

## Évolutions récentes déjà intégrées (état actuel du dépôt)

- `protocole/trace.py` : trace JSON optionnelle des événements du protocole.
  DÉSACTIVÉE par défaut (`TRACE_JSON` non défini ou `"0"`). Quand inactive, coût
  nul : `emettre()` retourne immédiatement sur un test de booléen, AVANT tout
  travail. Elle ne modifie jamais le comportement ni le résultat du protocole.
  Appels `trace.emettre(...)` présents dans kdc.py, service.py, client.py.
- `demo/` : tableau de bord (`tableau_de_bord.py` + `.html`) qui lit les lignes
  `TRACE_JSON ...` via `docker compose logs` pour animer les échanges en temps
  réel, et `attaque_rejeu_direct.py` qui rejoue une attaque réelle contre le
  déploiement en cours.
- `docker-compose.yml` : `TRACE_JSON: "${TRACE_JSON:-0}"` sur les trois services
  — donc trace inactive par défaut, activable ponctuellement par
  `TRACE_JSON=1 docker compose up` pour la démonstration uniquement.

  IMPORTANT (méthodologie chap. 7) : la trace active a un COÛT MESURÉ élevé
  (latence plus que doublée, débit réduit de plus de moitié). Toutes les mesures
  de performance du chapitre 7 ont été faites trace INACTIVE. Ne jamais mesurer
  avec `TRACE_JSON=1`. La trace ne sert QUE la démonstration visuelle.

## Statut de la démo vis-à-vis du mémoire

La démo n'est PAS un instrument de preuve de sécurité — elle ne prouve rien
qu'une exécution ne prouve. Elle est un OUTIL DE COMPRÉHENSION et de
DÉMONSTRATION : sa place est en annexe du mémoire et en direct à la soutenance,
présentée comme telle. Ne pas la présenter comme une validation formelle.

## Ce qui est fait et testé

- Modules : crypto (AES-256-GCM, HKDF), cadrage (TLV/TCP), messages (MSG1..MSG4).
- Entités : KDC (base JSON + serveur TCP), service (cache anti-rejeu atomique),
  client (orchestration).
- `tests_attaques.py` : 7 scénarios, tous repoussés — rejeu (direct + réseau),
  usurpation par client interne, ticket expiré, ticket/authentifiant altérés,
  concurrence sur le nonce.
- Déploiement : Dockerfile, docker-compose (bridge isolé, clés par volumes),
  phase 0 d'amorçage hors réseau.
- `mesures.py` : latence distribuée, décomposition par phase, débit.
- Mesures de référence (entre conteneurs, trace inactive) : latence médiane
  2,025 ms ; débit d'un client séquentiel ≈ 389 auth/s ; RAM ≈15 Mio (KDC),
  ≈20 Mio (service) ; CPU 19 %/30 % sous ≈400 auth/s.

## CHANTIER 1 — Tests transposables (attaques Kerberos)

CONTEXTE : le mémoire compare le protocole à Kerberos via les attaques recensées
par Díaz Motero et al. (2021). L'encadreur demande de VÉRIFIER concrètement,
sur le prototype, les attaques qui sont TRANSPOSABLES.

Distinction essentielle à préserver dans le code et les commentaires :
- Attaques NON transposables (cible absente chez nous) — NE PAS chercher à les
  tester, leur objet n'existe pas :
    * Golden Ticket → nécessite un TGT ; il n'y en a pas.
    * Kerberoasting, devinette de mot de passe → nécessitent des clés dérivées
      de mots de passe ; nos clés sont aléatoires.
- Attaques TRANSPOSABLES (à tester explicitement) :
    * **Analogue du Silver Ticket** : un détenteur de clé maîtresse valide forge
      un ticket pour un service dont il n'a pas la clé K_S. → DÉJÀ COUVERT par
      `test_usurpation_interne` (test 2). Tâche : RENOMMER/ÉTIQUETER ce test
      comme « analogue Silver Ticket », et ajouter en commentaire la
      correspondance avec Motero et al. (2021). Le protocole DOIT rejeter :
      le ticket forgé sous une mauvaise clé échoue à l'ouverture côté service.
    * **Analogue du Pass-the-Ticket** : un adversaire REJOUE un ticket
      légitime capturé (vol + réinjection), sans le forger. → DÉJÀ COUVERT en
      partie par `test_rejeu` (test 1) et `test_rejeu_reseau` (test 7). Tâche :
      AJOUTER un test dédié `test_pass_the_ticket` qui capture un MSG3 complet
      légitime et le rejoue ; vérifier qu'il est refusé PAR LE CACHE DE NONCES,
      et documenter que la protection est ÉGALEMENT bornée par l'expiration
      T_exp du ticket (rejeu après expiration → doublement refusé). Étiqueter
      « analogue Pass-the-Ticket » avec renvoi à Motero et al. (2021).

RÈGLE DE VÉRIFICATION (rappel) : un test « attaque » réussit quand le service
REFUSE (retourne None / pas de MSG4). Vérifier le TYPE de la réponse, pas
seulement sa présence : `resultat is None`, ou pour le nominal
`resultat[0] == cadrage.MSG4`.

Livrable : `tests_attaques.py` mis à jour, exécuté, tous scénarios repoussés,
avec un tableau récapitulatif en commentaire liant chaque test transposable à
son attaque Kerberos de référence.

## CHANTIER 2 — Montée en charge (à mesurer)

CONTEXTE : le chapitre 7 mesure le débit d'un SEUL client séquentiel
(≈389 auth/s) et dit explicitement que ce N'EST PAS la capacité du KDC.
L'encadreur demande combien de clients/services le protocole supporte.

Tâche : écrire un script de montée en charge (ex. `mesures_charge.py`) qui
lance N CLIENTS CONCURRENTS (threads ou processus) contre le déploiement, pour
N croissant (ex. 1, 5, 10, 20, 50), et relève à chaque niveau :
- débit agrégé (auth/s, tous clients confondus),
- latence médiane et p95 par authentification,
- taux d'échec.
Relever en parallèle `docker stats` (CPU/RAM du KDC et du service) pour situer
la saturation. Objectif : trouver le point où le débit cesse de croître et où la
latence décroche — c'est la capacité réelle, à opposer au débit séquentiel.

CADRAGE HONNÊTE (rappel pour la rédaction) :
- Mesurer trace INACTIVE.
- Mesurer ENTRE CONTENEURS (pas via ports publiés : le relais coûte ≈1,6 ms/
  connexion et fausse tout — résultat déjà établi au chap. 7).
- Ne pas extrapoler une capacité théorique depuis le CPU : mesurer le point de
  saturation réel.
- L'argument de scalabilité STRUCTURELLE (N+M clés maîtresses vs N×M en
  peer-to-peer) est théorique et démontrable SANS mesure ; il complète la
  mesure de charge mais ne la remplace pas.

## Ce qui NE se fait PAS ici

La rédaction des chapitres, les arbitrages bibliographiques et la cohérence
argumentative se poursuivent dans l'interface de rédaction. Rapporter ici les
chiffres et constats obtenus, puis rédiger là-bas.
