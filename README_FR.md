# OASI / AERA — aperçu de recherche

> PROTOTYPE DE RECHERCHE  
> AERA : IMPLÉMENTATION ET SPÉCIFICATION DE RÉFÉRENCE USER-SPACE BORNÉE  
> SYSTÈME OASI COMPLET : NON DÉMONTRÉ  
> RÉSULTAT SCIENTIFIQUE T4 : NÉGATIF / VALIDITÉ DE CONSTRUIT LIMITÉE  
> G039 : HOLD / AUCUN REPLAY  
> G040 : PRÉPARÉ UNIQUEMENT  
> NON PRÊT POUR LA PRODUCTION  
> AUCUNE REVENDICATION DE SUPÉRIORITÉ GÉNÉRALE  
> AUCUNE VALIDATION DARPA, IEEE OU INSTITUTIONNELLE

OASI est un programme de recherche fondé sur la thèse suivante : les activités du système d’exploitation, l’incarnation, l’organisation du système et l’intelligence pourraient appartenir à une même histoire causale développementale — `OS = IA = activité continue d’un même organisme artificiel`.

Cette version `v0.1.0-research-preview` ne démontre pas l’OASI complet. Elle publie une contribution plus étroite : AERA, un mécanisme de référence user-space dans lequel l’autorité est liée à l’identité corporelle, l’époque, la génération, le certificat, le principal, la ressource, l’action et l’expiration, puis revérifiée au moment du commit d’un effet.

## Contenu

- runtime Rust borné et tests publics ;
- spécification AERA et modèle de menaces ;
- matrice exacte des affirmations et preuves ;
- résultat T4 négatif et diagnostic de validité de construit ;
- documentation de reproductibilité, sécurité, licences et supply chain ;
- résumés publics et empreintes des preuves privées lourdes.

Le paquet Rust conserve son nom historique `osia-core-r1`; le programme de recherche public se nomme OASI/AERA.

## Identifiants pérennes

- Prépublication scientifique : [doi:10.5281/zenodo.22151556](https://doi.org/10.5281/zenodo.22151556)
- Aperçu logiciel : [doi:10.5281/zenodo.22151560](https://doi.org/10.5281/zenodo.22151560)
- Dépôt source : <https://github.com/mohammedmessaoudene-cmd/oasi-research>

## Vérification

Pré-requis pour la suite complète : Linux, Rust/Cargo 1.97.1 et Python 3.11 ou plus récent. Le sous-ensemble Windows/GNU est volontairement partiel, car certains tests vérifient explicitement `/proc` et `/bin`.

```text
cargo test --locked --all-targets
python -I -B tools/verify_release.py .
```

## Limites

Il ne s’agit ni d’un noyau, ni d’un hyperviseur, ni d’un système d’exploitation complet, ni d’un dossier de sûreté de production, ni d’une preuve universelle de sécurité, ni d’une conscience artificielle.

Le propriétaire a fourni une déclaration explicite de droits et de provenance pour cette release assainie. La recherche contradictoire dans l’arbre public n’a trouvé aucun autre contributeur humain nommé, identifiant de subvention ou de contrat, code tiers embarqué, notice incompatible ni matériel de laboratoire privé. Cette acceptation reste bornée à la release : ce n’est ni une décision judiciaire ni une validation institutionnelle.

Le code Rust historique et ses tests conservent `Apache-2.0 OR MIT`; les nouveaux outils et schémas originaux utilisent `Apache-2.0`; l’article, les figures, les spécifications, la documentation et les résumés publics utilisent `CC-BY-4.0`. L’AGPL n’est pas appliquée rétroactivement à v0.1.
