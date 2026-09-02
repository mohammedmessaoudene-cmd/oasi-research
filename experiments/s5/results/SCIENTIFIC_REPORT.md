# Rapport scientifique OASI S5 — local fixture-only

## Verdict

`PASS_CAMPAIGN / MECHANISM_ADVANTAGE_NOT_ESTABLISHED_AGAINST_B3`

La campagne pré-enregistrée a exécuté 1 200/1 200 runs, 40 cellules et 30
répétitions mesurées par cellule après cinq warmups exclus. Le vérificateur
indépendant recalcule les agrégats et conclut `PASS`. Aucun appel réseau, effet
réel, secret réel, QEMU, guest ou déploiement n'a été utilisé.

Ce résultat ne démontre pas un avantage scientifique global d'OASI. Il montre
un avantage de sûreté contre B0, B1 et B2 dans les fautes modélisées, mais pas
contre la baseline forte B3 à récepteur idempotent coopératif.

## Résultats primaires

| Mécanisme | Runs | Doubles effets | Livraisons exactement une fois | Rejeux acceptés | Cross-generation acceptés | Signatures altérées acceptées |
|---|---:|---:|---:|---:|---:|---:|
| B0 direct | 240 | 90 | 150 | 30 | 30 | 30 |
| B1 authentifié stateless | 240 | 90 | 90 | 30 | 0 | 0 |
| B2 at-least-once | 240 | 30 | 150 | 0 | 0 | 0 |
| B3 idempotent | 240 | 0 | 180 | 0 | 0 | 0 |
| OASI | 240 | 0 | 120 | 0 | 0 | 0 |

- H1 sûreté OASI : 0 double effet sur 240 runs; borne supérieure Wilson 95 %
  approximative 1,58 %. PASS borné, pas preuve de risque nul universel.
- H2 reprise : 240/240 runs OASI ont une disposition terminale déterministe.
  Toutefois, après crash en `CONSUMED`, OASI bloque sans rediffusion et livre
  zéro effet, alors que B3 récupère une livraison exactement une fois.
- H3 sécurité fixture : OASI rejette 30/30 rejeux, 30/30 frames
  cross-generation et 30/30 signatures altérées dans leurs cellules.
- H4 coût : toutes les mesures sont conservées; elles ne favorisent pas OASI.

## Cas discriminants

| Cellule | Doubles/30 | Livraison exacte/30 | p50 local |
|---|---:|---:|---:|
| B2 crash après effet avant résultat | 30 | 0 | 11,145 ms |
| B3 même crash | 0 | 30 | 10,569 ms |
| OASI même crash | 0 | 30 | 12,139 ms |
| B3 crash au point consommé modélisé | 0 | 30 | 10,066 ms |
| OASI crash après consommation | 0 | 0 | 11,067 ms |
| B3 nominal | 0 | 30 | 9,726 ms |
| OASI nominal | 0 | 30 | 17,316 ms |

En nominal, la médiane locale OASI est environ 1,78 fois celle de B3. Les
artefacts moyens nominaux sont 41 025 octets pour OASI contre 32 833 pour B3.
Ces chiffres décrivent Python/SQLite sous WSL1 sur cette machine seulement.

## Interprétation

OASI résout le double-effet lorsqu'un récepteur ne fournit pas lui-même une
déduplication transactionnelle fiable. Mais lorsque le récepteur B3 coopère et
persiste atomiquement sa clé d'idempotence avec l'effet, B3 égale la sûreté
observée, livre davantage d'effets après crash et coûte moins dans ce modèle.

Le prochain progrès scientifique ne doit donc pas être une nouvelle génération
cosmétique. Il faut formuler et tester la frontière précise où B3 n'est pas
disponible : effet externe non transactionnel, récepteur non coopératif ou clé
d'idempotence non imposable. Cette nouvelle expérience exige une prérégistration
distincte; elle peut rester fixture-only, sans effet externe réel.

## Frontière de claims

`PASS` signifie uniquement que la campagne locale et son vérificateur ont
réussi. Ce rapport n'établit ni sécurité de production, ni avantage général,
ni performance guest/QEMU, ni restauration matérielle, ni validation
indépendante externe, ni autorisation de publication.

