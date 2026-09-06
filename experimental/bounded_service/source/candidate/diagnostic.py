"""Bounded evidence-led expert rules, not an LLM or a causal proof engine."""
import hashlib,re

MAX_BYTES=524288
RULES={
 'ENOSPC':('Espace de stockage insuffisant signalé','Vérifier espace libre et quotas du volume concerné ; ne rien supprimer automatiquement.'),
 'EACCES':('Accès refusé signalé','Vérifier le chemin et les droits du compte du service ; ne pas élargir les permissions automatiquement.'),
 'EADDRINUSE':('Adresse déjà utilisée signalée','Identifier le service propriétaire de cette adresse avant toute modification ; ne terminer aucun processus automatiquement.'),
 'ENOMEM':('Allocation mémoire refusée signalée','Examiner la pression mémoire et les limites du service ; ne pas redémarrer automatiquement.'),
 'MODULE_NOT_FOUND':('Dépendance introuvable signalée','Vérifier l’environnement et la dépendance attendue ; ne rien télécharger ni installer automatiquement.'),
 'ETIMEDOUT':('Délai dépassé signalé','Examiner les événements corrélés et la disponibilité de la dépendance ; ne pas relancer automatiquement une action.'),
}
SERVICE=re.compile(r'[A-Za-z0-9_.-]{1,32}\Z')
FIELD=re.compile(r'(?:^| )([A-Za-z_]+)=([^ ]+)')

def excerpt(line):
    line=re.sub(r'(?i)\b(password|token|secret|api_key|authorization)=([^ ]+)',r'\1=[MASQUÉ]',line)
    return ''.join(c if c.isprintable() else ' ' for c in line)[:240]

def analyze(data):
    if not isinstance(data,bytes):raise TypeError('bytes required')
    base={'schema':1,'kind':'BOUNDED_EXPERT_RULES','input_sha256':hashlib.sha256(data).hexdigest(),
          'bytes':len(data),'findings':[],'abstentions':[],'actions_executed':0,
          'understanding_claim':'STRUCTURED_SIGNALS_ONLY_NOT_GENERAL_UNDERSTANDING'}
    def refuse(reason):return {**base,'status':'ABSTAIN','reason':reason}
    if len(data)>MAX_BYTES:return refuse('INPUT_TOO_LARGE')
    if b'\0' in data:return refuse('BINARY_NUL')
    try:text=data.decode('utf-8','strict')
    except UnicodeDecodeError:return refuse('INVALID_UTF8')
    lines=text.splitlines()
    if len(lines)>10000:return refuse('TOO_MANY_LINES')
    if any(len(line.encode('utf-8'))>4096 for line in lines):return refuse('LINE_TOO_LONG')
    states={};abstentions=[]
    for number,line in enumerate(lines,1):
        if not line.startswith('LEVEL='):
            if re.search(r'\b(?:ERROR|FATAL|EXCEPTION)\b',line):abstentions.append({'line':number,'reason':'UNSTRUCTURED_SIGNAL'})
            continue
        pairs=FIELD.findall(line);fields=dict(pairs)
        if len(pairs)!=len(fields):abstentions.append({'line':number,'reason':'DUPLICATE_FIELD'});continue
        level=fields.get('LEVEL');code=fields.get('code');service=fields.get('service');event=fields.get('event')
        if level=='INFO' and event!='RECOVERED':continue
        if level not in ('ERROR','INFO') or (level=='ERROR' and event not in (None,'FAILURE')):
            abstentions.append({'line':number,'reason':'UNSUPPORTED_EVENT'});continue
        if fields.get('negated')=='true' or fields.get('test')=='true':
            abstentions.append({'line':number,'reason':'NEGATED_OR_TEST'});continue
        if code not in RULES:
            abstentions.append({'line':number,'reason':'UNKNOWN_CODE'});continue
        if not service or not SERVICE.fullmatch(service):
            abstentions.append({'line':number,'reason':'UNKNOWN_SCOPE'});continue
        key=(service,code)
        if key not in states:
            if level=='INFO':abstentions.append({'line':number,'reason':'RECOVERY_WITHOUT_OBSERVED_ERROR'});continue
            if len(states)>=64:return refuse('TOO_MANY_INCIDENT_GROUPS')
            states[key]={'service':service,'code':code,'active':False,'occurrences':0,'history':[],
                         'hypothesis':RULES[code][0],'suggested_check':RULES[code][1],'hypothesis_only':True}
        item=states[key];item['active']=level=='ERROR'
        item['occurrences']+=int(level=='ERROR')
        item['history'].append({'line':number,'event':'ERROR' if level=='ERROR' else 'RECOVERED','excerpt':excerpt(line)})
        item['history']=item['history'][-8:]
    if len(abstentions)>128:return refuse('TOO_MANY_UNSUPPORTED_SIGNALS')
    base.update(findings=[states[k] for k in sorted(states)],abstentions=abstentions,
                status='PARTIAL_ABSTENTION' if abstentions else ('SUPPORTED_FINDINGS' if any(v['active'] for v in states.values()) else 'NO_ACTIVE_SUPPORTED_INCIDENT'))
    return base

def render(result):
    lines=['Diagnostic consultatif — signaux structurés, aucune action exécutée.', 'État : '+result['status']]
    if 'reason' in result:lines.append('Abstention : '+result['reason'])
    for item in result['findings']:
        lines.append(f"{item['service']} / {item['code']} : {'ACTIF' if item['active'] else 'RÉCUPÉRATION SIGNALÉE'} — {item['occurrences']} occurrence(s)")
        lines.append('Hypothèse : '+item['hypothesis'])
        lines.append('Vérification proposée : '+item['suggested_check'])
        for e in item['history']:lines.append(f"  Ligne {e['line']} [{e['event']}] : {e['excerpt']}")
    for abstention in result['abstentions']:lines.append(f"Ligne {abstention['line']} : abstention ({abstention['reason']})")
    return '\n'.join(lines)
