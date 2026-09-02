# Preuves de test S6

- Preflight : `PASS_S6_PREFLIGHT`, six entrées épinglées, résultats et scratch
  absents, vérificateur détaché, garde réseau et récepteur non coopératif.
- Tests unitaires : 7/7 PASS, incluant API sans idempotency key, différence B3/OASI
  après accusé perdu, contrepartie pré-effet et anti-rejeu.
- Campagne : 1 500/1 500 mesures et 50/50 cellules complètes.
- Vérification détachée : PASS, zéro violation OASI, zéro réseau.

Pour l'interprétation scientifique publiable, voir
`../INTERPRETATION_NOTICE.md` : le verdict interne historique, les intervalles
de Wilson et le terme « indépendant » ne constituent pas la conclusion v0.2.
- Test rouge/vert matériel : un résultat OASI muté à deux effets est rejeté avec
  `OASI safety violation`; le corpus original est accepté.
