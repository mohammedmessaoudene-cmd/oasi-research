# OASI — Operational Artificial System Intelligence / AERA — aperçu de recherche

> PROTOTYPE DE RECHERCHE  
> AERA : IMPLÉMENTATION ET SPÉCIFICATION DE RÉFÉRENCE USER-SPACE BORNÉE  
> SYSTÈME OASI COMPLET : NON DÉMONTRÉ  
> RÉSULTAT SCIENTIFIQUE T4 : NÉGATIF / VALIDITÉ DE CONSTRUIT LIMITÉE  
> G039 : HOLD / AUCUN REPLAY  
> G040 : PRÉPARÉ UNIQUEMENT  
> NON PRÊT POUR LA PRODUCTION  
> AUCUNE REVENDICATION DE SUPÉRIORITÉ GÉNÉRALE  
> AUCUNE VALIDATION DARPA, IEEE OU INSTITUTIONNELLE

**Operational Artificial System Intelligence (OASI)** est le nom canonique du
paradigme de recherche documenté par ce projet. Il étudie une architecture dans
laquelle l’opération du système, l’incarnation artificielle, la mémoire, la
cognition, l’autorité et le développement sont coordonnés par une même histoire
causale versionnée et des effets soumis à une constitution. Sa thèse technique
reste : `OS = IA = activité continue d’un même organisme artificiel`.

Dans ce nom, **Operational** désigne l’activité opératoire du système et non un
niveau de maturité prêt pour la production. **System Intelligence** désigne une
cible de recherche ; ce nom ne revendique ni intelligence générale ou
superintelligence accomplie, ni conscience, unité organismique démontrée,
déploiement, validation externe ou supériorité.

Cette version `v0.2.1-research-preview` ne démontre pas l’OASI complet. Elle publie la contribution AERA bornée et deux simulations locales déterministes de la frontière d’effet. Leur conclusion est négative ou diagnostique : S5 n’établit pas d’avantage face à un récepteur idempotent coopératif et S6 révèle un compromis rediffusion/omission sans isoler un avantage propre à OASI.

## Contenu

- runtime Rust borné et tests publics ;
- spécification AERA et modèle de menaces ;
- prépublication v0.4 et analyse contradictoire S5/S6 ;
- 2 700 traces déterministes, données brutes, scripts relocalisables sous
  Linux/WSL et qualifiés sous WSL1 x86_64, tests,
  vérificateurs d’agrégats, protocoles et dictionnaire de données ;
- matrice exacte des affirmations et preuves ;
- résultat T4 négatif et diagnostic de validité de construit ;
- documentation de reproductibilité, sécurité, licences et supply chain ;
- résumés publics et empreintes des preuves privées lourdes.

Le paquet Rust conserve son nom historique `osia-core-r1` et sa version
`0.1.0-research-preview`, car son code est inchangé. `v0.2` désigne l'ensemble
de publication ajoutant S5/S6 et l'article v0.4 ; le programme de recherche
public associe OASI, nom du paradigme Operational Artificial System
Intelligence, à l’hypothèse d’architecture organismique et au mécanisme AERA.

## Identifiants pérennes actuels (v0.2/v0.4)

- Prépublication scientifique v0.4 : [doi:10.5281/zenodo.22262138](https://doi.org/10.5281/zenodo.22262138)
- Aperçu logiciel/données agrégé v0.2 : [doi:10.5281/zenodo.22262143](https://doi.org/10.5281/zenodo.22262143)

Ces deux DOI de version distincts ont été réservés avant la construction finale
des livrables. Chacun est résolu par Zenodo lorsque la notice correspondante
est publique ; les notices article et logiciel restent séparées à cause de
leurs périmètres de licence différents.

## Identifiants pérennes historiques (v0.1)

- Prépublication scientifique antérieure v0.3 : [doi:10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)
- Aperçu logiciel antérieur v0.1 : [doi:10.5281/zenodo.22151560](https://doi.org/10.5281/zenodo.22151560)
- Dépôt source : <https://github.com/mohammedmessaoudene-cmd/oasi-research>

Ces deux notices Zenodo historiques restent les identifiants des livrables
v0.1 et n'identifient pas cette version v0.2/v0.4.

## Vérification

Le lanceur qualifié de la suite complète exige Linux x86_64, les builds exacts
Rust/Cargo 1.97.1 consignés dans `TOOLCHAIN_PROVENANCE.json`, ainsi que CPython
3.12.3, PyYAML 6.0.1, cryptography 41.0.7 et SQLite 3.45.1 exactement. Le
sous-ensemble Windows/GNU utilise l'environnement de publication épinglé et
reste volontairement partiel, car certains tests vérifient explicitement
`/proc` et `/bin`. D'autres environnements Python 3.11+ peuvent servir à une
reproduction manuelle exploratoire, mais ils ne font pas partie de la surface
qualifiée du lanceur.

```text
sh tools/run_tests.sh post-doi
```

## Limites

Il ne s’agit ni d’un noyau, ni d’un hyperviseur, ni d’un système d’exploitation complet, ni d’un dossier de sûreté de production, ni d’une preuve universelle de sécurité, ni d’une conscience artificielle.

Les 30 répétitions par cellule S5/S6 ne sont pas des échantillons indépendants.
Les crashs, déconnexions et écritures déchirées sont des traces simulées. S6
compare principalement une politique de rediffusion à une politique
at-most-once sans rediffusion : elle montre un compromis sûreté--disponibilité,
pas une garantie exactly-once ni une supériorité générale.

Le propriétaire a fourni une déclaration explicite de droits et de provenance pour cette release assainie. La recherche contradictoire dans l’arbre public n’a trouvé aucun autre contributeur humain nommé, identifiant de subvention ou de contrat, code tiers embarqué, notice incompatible ni matériel de laboratoire privé. Cette acceptation reste bornée à la release : ce n’est ni une décision judiciaire ni une validation institutionnelle.

Le code Rust historique et ses tests conservent `Apache-2.0 OR MIT`; les nouveaux outils, scripts d’expérience et schémas originaux utilisent `Apache-2.0`; l’article, les figures, les données, les spécifications, la documentation et les résumés publics utilisent `CC-BY-4.0`. L’AGPL n’est pas appliquée rétroactivement.
