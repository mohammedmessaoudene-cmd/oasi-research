# OASI — résultats expérimentaux

## v0.4.0 — vérifier l'expérience sur la règle acquise

Le [paquet de résultats](public_evidence/operant_r1/oasi-operant-results.zip) permet de recalculer les sorties enregistrées sans installer OASI. Après extraction, ouvrir le dossier `oasi-operant-results` et lancer `python -B -E -s -S verify_results.py` avec Python 3.11. C'est une relecture des données, pas une nouvelle exécution de l'expérience.

Quand la capacité du tampon diminue, OASI change la demande qu'il adresse au garde. Sur les quatre situations du même calcul, les quatre méthodes obtiennent toutes la sortie attendue. Le contrôleur classique utilisant le même arbre suit la même trajectoire qu'OASI : 104 unités de travail chacun, contre 100 pour le planificateur et 100 pour le cache avec replanification. Aucun avantage propre à OASI n'est démontré. L'article et les anciennes versions demeurent inchangés.

## Version expérimentale v0.3.0

Le projet avance techniquement : un service local analyse des fichiers synthétiques, conserve ses résultats, suit son budget et reprend une tâche interrompue sans rembourser son exécution précédente. Ce n'est pas encore l'organisme informatique complet visé par OASI.

## Vérifier en une commande, sans lancer le service
```sh
python -B experimental/bounded_service/verify_portable.py experimental/bounded_service/BOUNDED_SERVICE_PUBLIC_EVIDENCE.zip
```
Python 3.11+ déjà installé suffit. Aucune installation, compilation, opération privilégiée, connexion ou exécution de tâche. Les chemins historiques sont des identités opaques : aucun fichier personnel n'est ouvert.

Le recalcul porte sur 168 snapshots, 16 réservations, 16 débuts et 15 résultats exacts. L'interruption contrôlée suivie de reprise consomme deux places. Les 70 commandes ne sont pas 70 travaux. Les 28 décisions sont comptées ; le nouvel oracle ne revalide pas tout l'algorithme d'apprentissage.

Le dossier public est un dérivé expurgé, pas l'archive brute : chemins, bindings de réservation et liens de chaîne correspondants ont été normalisés. La correspondance originale/dérivée a été contrôlée localement. Elle ne constitue pas une attestation extérieure.

Les sources sont fournies sans binaire ; le service n'est donc pas présenté comme un installateur prêt à l'emploi. Le mode SHA256 seul n'a pas été qualifié séparément. Pas de résistance aux coupures électriques, d'isolation PID1 de ce service ou d'avantage scientifique démontré. La revue Pro provient d'un autre assistant IA, pas d'un laboratoire indépendant.

L'article, le noyau Rust publié et les expériences S5/S6 antérieures sont conservés sans modification. [Détails](RELEASE_NOTES_V0_3.md) — [documentation du module](experimental/bounded_service/README.md).
