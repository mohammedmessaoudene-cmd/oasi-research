# Protocole pré-enregistré OASI S6

Statut avant mesure : `LOCKED_BEFORE_OBSERVATION`.

## Récepteur fixture

`NON_COOPERATIVE_APPEND_ONLY_V1` accepte uniquement `apply(payload)`. Il ne
fournit aucune clé d'idempotence, transaction atomique partagée, déduplication,
requête de résultat ou statut par identifiant. Son stockage SQLite sert
uniquement à rendre l'observation locale comptable; les mécanismes comparés ne
peuvent pas le consulter pour résoudre une issue ambiguë.

`B3_IDEMPOTENT_UNAVAILABLE` conserve le coordinateur durable et la demande
conceptuelle d'idempotence de B3, mais le récepteur ne possède aucun point API
pour l'honorer. Il redélivre donc un travail `READY` comme B2. Ce scénario ne
prétend pas que B3 échoue avec un récepteur coopératif; S5 a testé ce cas.

## Mécanismes et cas

- B0 direct; B1 authentifié stateless; B2 at-least-once;
  B3 idempotence indisponible; OASI ledger S1 gelé.
- Cas : nominal, replay, cross-generation, signature altérée, crash PREPARED,
  crash CONSUMED avant effet, déconnexion avant effet, déconnexion après effet,
  accusé perdu après effet, écriture déchirée après effet.

## Plan et métriques

- graine racine `20260903`;
- cinq warmups exclus et exactement 30 répétitions conservées pour chacune des
  50 cellules, soit 1 500 lignes brutes;
- sûreté : double-effet, rejeu et bindings acceptés;
- reprise : livraison exactement une fois, perte de livraison, disposition;
- coût : latence p50/p95/p99, CPU, pic heap Python, delta RSS et stockage;
- réseau Python bloqué, effet NOOP fixture-only et aucun secret réel.

## Hypothèses et verdict pré-enregistrés

H1 est satisfaite si, dans `disconnect_after_effect` et
`ack_lost_after_effect`, OASI observe zéro double-effet et B3 indisponible en
observe au moins un. H2 exige de rapporter la contrepartie : dans les trois cas
pré-effet, OASI peut perdre une livraison parce qu'il refuse une rediffusion
ambiguë alors que B3/B2 redélivrent.

Le seul verdict positif autorisé est
`BOUNDED_SAFETY_ADVANTAGE_ESTABLISHED_NON_COOPERATIVE_FIXTURE_WITH_AVAILABILITY_TRADEOFF`.
Il ne signifie ni supériorité générale, ni exactly-once universel, ni résultat
QEMU/guest/matériel, ni production, ni validation externe.

