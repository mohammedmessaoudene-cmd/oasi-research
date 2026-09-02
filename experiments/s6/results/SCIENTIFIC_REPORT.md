# Rapport scientifique OASI S6 — récepteur non coopératif fixture-only

## Verdict

`PASS_CAMPAIGN / BOUNDED_SAFETY_ADVANTAGE_ESTABLISHED_NON_COOPERATIVE_FIXTURE_WITH_AVAILABILITY_TRADEOFF`

La campagne pré-enregistrée a exécuté 1 500/1 500 mesures, 50 cellules et 30
répétitions par cellule après cinq warmups exclus. Le vérificateur indépendant
recalcule toutes les cellules et conclut `PASS`. Aucun appel réseau, effet réel,
secret réel, QEMU, guest, déploiement ou publication n'a été utilisé.

## Résultat principal

Dans les deux cellules d'ambiguïté post-effet pré-enregistrées
(`disconnect_after_effect`, `ack_lost_after_effect`) :

| Mécanisme | Runs | Doubles effets | Livraisons exactement une fois |
|---|---:|---:|---:|
| B3, idempotence indisponible côté récepteur | 60 | 60 | 0 |
| OASI | 60 | 0 | 60 |

La proportion observée de double-effet est 100 % pour B3 et 0 % pour OASI.
Les intervalles Wilson 95 % sont approximativement [93,98 %, 100 %] et
[0 %, 6,02 %]. Cela établit l'avantage de sûreté uniquement dans ce modèle
fixture borné : le récepteur append-only n'accepte ni clé de déduplication, ni
transaction partagée, ni requête d'état.

## Contrepartie de disponibilité

Dans les trois cellules d'ambiguïté pré-effet pré-enregistrées (`crash_prepared`,
`crash_consumed_before_effect`, `disconnect_before_effect`) :

| Mécanisme | Runs | Pertes de livraison | Livraisons exactement une fois |
|---|---:|---:|---:|
| B3, idempotence indisponible côté récepteur | 90 | 0 | 90 |
| OASI | 90 | 90 | 0 |

OASI privilégie donc l'absence de double-effet au prix d'une sémantique
at-most-once : après consommation durable, une issue inconnue bloque la
rediffusion, même si l'effet n'a finalement pas eu lieu. Le résultat ne prouve
pas un exactly-once universel.

## Totaux descriptifs

| Mécanisme | Runs | Doubles | Livraisons exactes | Pertes | Rejeux acceptés | Cross-generation | Signatures altérées |
|---|---:|---:|---:|---:|---:|---:|---:|
| B0 direct | 300 | 120 | 180 | 0 | 30 | 30 | 30 |
| B1 authentifié stateless | 300 | 120 | 120 | 0 | 30 | 0 | 0 |
| B2 at-least-once | 300 | 60 | 180 | 0 | 0 | 0 | 0 |
| B3 idempotence indisponible | 300 | 60 | 180 | 0 | 0 | 0 | 0 |
| OASI | 300 | 0 | 150 | 90 | 0 | 0 | 0 |

## Coûts locaux indicatifs

| Cellule | p50 latence locale | CPU moyen | Heap max | Artefacts moyens |
|---|---:|---:|---:|---:|
| B3 nominal | 9,925 ms | 7,292 ms | 24 605 o | 24 641 o |
| OASI nominal | 17,078 ms | 14,063 ms | 34 331 o | 32 833 o |
| B3 déconnexion après effet | 11,975 ms | 10,417 ms | 26 408 o | 24 641 o |
| OASI déconnexion après effet | 12,691 ms | 8,854 ms | 30 971 o | 32 833 o |

Ces chiffres décrivent Python/SQLite sous WSL1 sur cette machine. Ils ne sont
pas un benchmark guest, QEMU, matériel ou production.

## Interprétation et frontière des claims

S5 avait montré que B3 coopératif égale la sûreté observée d'OASI tout en
récupérant davantage de livraisons. S6 montre le domaine complémentaire : si
le récepteur ne peut pas honorer l'idempotence, le coordinateur B3 ne peut pas
éliminer l'ambiguïté post-effet, tandis que la consommation durable préalable
d'OASI empêche la rediffusion et le double-effet.

Le résultat est une preuve expérimentale locale reproductible d'un compromis
sûreté/disponibilité dans un modèle précis. Il n'établit ni supériorité générale,
ni sécurité de production, ni validation indépendante externe, ni performance
réelle, ni autorisation de publication.

