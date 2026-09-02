# Protocole pré-enregistré OASI S5

Statut avant mesure : `LOCKED_BEFORE_OBSERVATION`.

## Mécanismes

- `B0_DIRECT`: dispatch direct, sans authentification ni état durable.
- `B1_AUTH_STATELESS`: Ed25519 fixture et binding génération/contexte, sans
  mémoire anti-rejeu.
- `B2_AT_LEAST_ONCE`: B1 + coordinateur SQLite durable; redélivre un travail
  `READY` après crash, effet non idempotent.
- `B3_IDEMPOTENT`: B2 + récepteur local transactionnel à clé de déduplication.
- `OASI`: `Ledger` S1 gelé, consommation durable avant dispatch et blocage de
  toute rediffusion ambiguë.

Toutes les clés sont des fixtures RFC8032 publiques et documentées. Aucun
secret de production ou effet réel n'est utilisé.

## Cas exacts

`nominal`, `replay`, `cross_generation`, `altered_signature`,
`crash_prepared`, `crash_consumed`, `crash_after_effect_before_result`,
`torn_write`.

Les absences de phase dans B0/B1 sont modélisées honnêtement comme une reprise
par rediffusion. B2/B3 n'ont pas de phase `CONSUMED`; leur reprise depuis
`READY` est une redélivrance. OASI abandonne sans effet depuis `PREPARED` et
bloque sans rediffusion depuis `CONSUMED`.

## Plan de mesure

- cinq warmups par cellule, enregistrés seulement comme compte et exclus;
- 30 répétitions mesurées par cellule, donc 1 200 lignes brutes;
- graine racine `20260902`, graine de répétition indépendante du mécanisme;
- ordre des cinq mécanismes mélangé de façon déterministe par cas/répétition;
- même payload NOOP, même effet SQLite et même machine;
- exécution sous WSL sur x86_64, scratch sur le système de fichiers Linux local,
  résultats copiés vers un volume non système ;
- garde réseau Python active; zéro socket autorisée.

## Métriques pré-enregistrées

- `double_effect`, `effect_count`, rejeu/cross-generation/signature acceptés;
- état terminal déterministe et livraison d'un effet attendu;
- latence murale en ns : p50/p95/p99 et moyenne;
- CPU processus en ns;
- pic d'allocation Python `tracemalloc` et delta RSS observé;
- octets du ledger/coordonateur/récepteur;
- intervalles de Wilson 95 % pour les proportions et différences de risque.

Les mesures mémoire ne sont pas des mesures de mémoire guest ou système
complète. La latence est une micro-mesure locale Python/SQLite, pas un benchmark
QEMU ou production.

## Critères d'arrêt et conclusion

- arrêt immédiat si OASI produit `effect_count > 1`, accepte un rejeu, une
  signature altérée ou un frame cross-generation;
- arrêt si un pin dérive, si le réseau est utilisé, si une cellule manque ou si
  un artefact préexistant ferait rejouer une campagne;
- OASI n'est déclaré supérieur globalement que s'il bat aussi B3 sur le critère
  primaire de sûreté sans dégrader la reprise; une égalité ou domination B3
  impose `MECHANISM_ADVANTAGE_NOT_ESTABLISHED_AGAINST_B3`;
- les coûts sont rapportés même défavorables; aucune métrique post-hoc cachée.
