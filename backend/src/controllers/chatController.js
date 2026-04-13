const Alert = require('../models/Alert');

const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.0-flash';

const TOPIC_KEYWORDS = [
  'securite', 'security', 'soc', 'siem', 'wazuh', 'cortex', 'iris', 'incident', 'alerte', 'alert',
  'threat', 'ioc', 'malware', 'phishing', 'ransomware', 'firewall', 'rule', 'mitre',
  'database', 'base de donne', 'mongodb', 'mongo', 'db', 'query', 'table', 'collection',
  'api', 'backend', 'frontend', 'dashboard', 'ai score', 'classification', 'risk score', 'mttd', 'mttr'
];

const SECURITY_GLOSSARY = {
  soc: 'Un SOC (Security Operations Center) est une equipe qui surveille en continu, detecte les menaces, investigue les alertes et coordonne la reponse a incident.',
  ioc: 'Un IOC (Indicator of Compromise) est une trace observable d\'attaque: hash malveillant, IP suspecte, domaine, URL, processus ou comportement anormal.',
  siem: 'Un SIEM centralise les logs, correle les evenements et declenche des alertes pour accelerer la detection et l\'investigation.',
  soar: 'Un SOAR automatise les playbooks de reponse (enrichissement, containment, notifications) pour reduire le temps de traitement.',
  edr: 'Un EDR surveille et protege les endpoints (postes/serveurs) avec detection comportementale et capacites de reponse.',
  xdr: 'Un XDR etend la detection et la reponse sur plusieurs couches (endpoint, reseau, email, cloud) dans une vue unifiee.',
  phishing: 'Le phishing est une tentative de vol d\'identifiants ou de donnees via emails/messages frauduleux se faisant passer pour une source legitime.',
  ransomware: 'Un ransomware chiffre les donnees pour exiger une rancon. Les defenses cle sont sauvegardes testees, segmentation, MFA et durcissement.',
  mitre: 'MITRE ATT&CK est une base de techniques d\'attaque utilisee pour mapper les detections et identifier les angles morts.',
  mttd: 'MTTD (Mean Time To Detect) est le temps moyen pour detecter un incident apres son debut.',
  mttr: 'MTTR (Mean Time To Respond/Recover) est le temps moyen pour contenir et restaurer apres detection d\'incident.',
  virustotal: 'VirusTotal est un service d\'analyse qui verifie fichiers, URLs, IP et domaines avec de nombreux moteurs de detection pour identifier des indicateurs malveillants.',
};

const SECURITY_TOPIC_GUIDANCE = {
  phishing: 'Plan anti-phishing: activer MFA, former les utilisateurs, bloquer domaines malveillants, analyser les pieces jointes en sandbox et isoler les comptes compromis.',
  ransomware: 'Plan anti-ransomware: sauvegardes hors ligne testees, segmentation reseau, patch management, protection EDR et procedure d\'isolation immediate.',
  malware: 'Gestion malware: quarantaine endpoint, collecte IOC, recherche laterale, suppression artefacts persistance et verification post-remediation.',
  ioc: 'Utilisation IOC: valider la source, corriger faux positifs, enrichir avec contexte (host/user/time), puis deployer regles de detection SIEM/EDR.',
  soc: 'Operation SOC: triage par severite/impact, investigation timeline, containment, puis retour d\'experience et tuning des regles.',
  siem: 'Optimiser SIEM: normaliser logs, prioriser cas d\'usage critiques, reduire bruit, mesurer couverture MITRE et precision des regles.',
  edr: 'EDR efficace: policy de blocage comportemental, isolation host, collecte telemetry, threat hunting et durcissement endpoint.',
  xdr: 'XDR: correler endpoint, email, cloud et reseau pour reduire le temps de detection et accelerer la reponse.',
  mitre: 'MITRE ATT&CK: mapper chaque alerte a une technique, identifier les lacunes de detection et planifier l\'amelioration de couverture.',
};

function normalizeText(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hasAny(text, keywords) {
  return keywords.some((kw) => text.includes(kw));
}

function detectAnswerMode(text) {
  if (hasAny(text, ['detail', 'detaille', 'explique', 'approfond', 'etape', 'procedure', 'pourquoi', 'analyse complete'])) {
    return 'long';
  }

  const words = text.split(' ').filter(Boolean).length;
  if (words <= 5 || hasAny(text, ['c est quoi', 'quest ce que', 'what is', 'definition'])) {
    return 'short';
  }

  return 'medium';
}

function pickByMode(mode, shortText, mediumText, longText) {
  if (mode === 'short') return shortText;
  if (mode === 'long') return longText;
  return mediumText;
}

function extractSubjectFromQuestion(text) {
  const patterns = [
    'c est quoi ',
    'quest ce que ',
    'que est ce que ',
    'qu est ce que ',
    'quest un ',
    'qu est un ',
    'what is ',
    'tell me about ',
    'define ',
    'definir ',
  ];

  for (const pattern of patterns) {
    if (text.startsWith(pattern)) {
      return text.slice(pattern.length).trim();
    }
  }

  return '';
}

function findGlossaryTerm(text) {
  if (hasAny(text, ['virus total', 'virustotal', 'virs total'])) {
    return 'virustotal';
  }
  const entries = Object.keys(SECURITY_GLOSSARY);
  return entries.find((term) => text.includes(term));
}

function inferSecurityTopic(text) {
  if (hasAny(text, ['virus total', 'virustotal', 'virs total'])) return 'virustotal';
  if (text.includes('phishing')) return 'phishing';
  if (text.includes('ransomware')) return 'ransomware';
  if (text.includes('malware')) return 'malware';
  if (text.includes('ioc')) return 'ioc';
  if (text.includes('soc')) return 'soc';
  if (text.includes('siem')) return 'siem';
  if (text.includes('edr')) return 'edr';
  if (text.includes('xdr')) return 'xdr';
  if (text.includes('mitre')) return 'mitre';
  return null;
}

function isSocDefinitionQuestion(text) {
  const asksDefinition = hasAny(text, [
    'c est quoi',
    'quest ce que',
    'que est ce que',
    'qu est ce que',
    'quest un',
    'qu est un',
    'definir',
    'definition',
    'what is',
    'explain',
  ]);
  return text.includes('soc') && asksDefinition;
}

function isAlertCountQuestion(text) {
  const asksCount = hasAny(text, ['combien', 'combient', 'how many', 'nombre', 'total']);
  const mentionsAlerts = hasAny(text, ['alert', 'alerte', 'dalerte', 'dalerte', 'daletre', 'incident']);
  return asksCount && mentionsAlerts;
}

function formatCounts(context) {
  return `Alertes actuelles: total=${context.totalAlerts}, open=${context.openAlerts}, investigating=${context.investigatingAlerts}, closed=${context.closedAlerts}.`;
}

function formatSecurityTip(context) {
  return 'Conseil SOC: prioriser CRITICAL/HIGH, verifier les faux positifs, et suivre MTTD/MTTR pour mesurer l\'efficacite.';
}

function buildFallbackReply(message, context, reason) {
  const normalized = normalizeText(message);
  const counts = formatCounts(context);
  const glossaryTerm = findGlossaryTerm(normalized);
  const topic = inferSecurityTopic(normalized);
  const mode = detectAnswerMode(normalized);
  const inferredSubject = extractSubjectFromQuestion(normalized);

  if (hasAny(normalized, ['bonjour', 'salut', 'hello', 'hi'])) {
    return pickByMode(
      mode,
      'Bonjour. Pose ta question, je reponds de facon concise.',
      'Bonjour. Pose ta question sur le sujet de ton choix, je reponds directement.',
      'Bonjour. Je peux repondre sur le sujet de ton choix. Si tu veux une meilleure precision, ajoute le contexte et le format souhaite.'
    );
  }

  if (isAlertCountQuestion(normalized)) {
    return `${counts} Il y a ${context.totalAlerts} alertes en base actuellement.`;
  }

  if (hasAny(normalized, ['lien', 'link', 'url']) && hasAny(normalized, ['virus total', 'virustotal', 'virs total'])) {
    return 'Lien officiel VirusTotal: https://www.virustotal.com/gui/home/upload . Tu peux analyser un fichier, une URL, une IP ou un domaine.';
  }

  if (hasAny(normalized, ['formule', 'formula']) && hasAny(normalized, ['mttd', 'detect'])) {
    return 'Formule MTTD: MTTD = somme des (date_detection - date_debut_incident) / nombre_incidents.';
  }

  if (hasAny(normalized, ['formule', 'formula']) && hasAny(normalized, ['mttr', 'response', 'recover'])) {
    return 'Formule MTTR: MTTR = somme des (date_resolution - date_detection) / nombre_incidents.';
  }

  if (hasAny(normalized, ['comment', 'calculer', 'calculate', 'compute']) && hasAny(normalized, ['mttd'])) {
    return 'Pour calculer MTTD: 1) note l heure de debut de chaque incident, 2) note l heure de detection, 3) fais la moyenne des delais de detection.';
  }

  if (hasAny(normalized, ['comment', 'calculer', 'calculate', 'compute']) && hasAny(normalized, ['mttr'])) {
    return 'Pour calculer MTTR: 1) note l heure de detection, 2) note l heure de resolution, 3) fais la moyenne des delais de remediation.';
  }

  if (isSocDefinitionQuestion(normalized)) {
    return SECURITY_GLOSSARY.soc;
  }

  if (topic && hasAny(normalized, ['comment', 'how to', 'etape', 'procedure', 'plan'])) {
    return SECURITY_TOPIC_GUIDANCE[topic] || formatSecurityTip(context);
  }

  if (hasAny(normalized, ['difference', 'diff', 'vs']) && hasAny(normalized, ['edr', 'xdr'])) {
    return 'Difference EDR vs XDR: EDR couvre surtout les endpoints. XDR correle plusieurs sources (endpoint, email, cloud, reseau) pour detecter et repondre plus vite.';
  }

  if (hasAny(normalized, ['difference', 'diff', 'vs']) && hasAny(normalized, ['siem', 'soar'])) {
    return 'Difference SIEM vs SOAR: SIEM detecte/correle les evenements. SOAR orchestre et automatise les actions de reponse via playbooks.';
  }

  if (inferredSubject) {
    return pickByMode(
      mode,
      `${inferredSubject} est un concept qui depend du contexte.`,
      `${inferredSubject}: c est un sujet que je peux expliquer. Si tu veux, je peux te donner definition, exemples, avantages et limites.`,
      `${inferredSubject}: je peux te repondre en detail avec 1) definition claire, 2) fonctionnement, 3) cas d usage, 4) limites, 5) bonnes pratiques. Ecris "detail ${inferredSubject}" pour la version complete.`
    );
  }

  if (
    glossaryTerm &&
    hasAny(normalized, [
      'c est quoi',
      'quest ce que',
      'que est ce que',
      'qu est ce que',
      'quest un',
      'qu est un',
      'what is',
      'tell me about',
      'definition',
      'definir',
      'explain',
    ])
  ) {
    return SECURITY_GLOSSARY[glossaryTerm];
  }

  if (glossaryTerm) {
    return SECURITY_GLOSSARY[glossaryTerm];
  }

  if (hasAny(normalized, ['triage', 'priorite', 'prioriser', 'priorisation'])) {
    return 'Triage recommande: 1) traiter CRITICAL/HIGH, 2) valider impact actif, 3) isoler endpoint si compromission, 4) ouvrir investigation avec preuves (IOC, logs, timeline).';
  }

  if (hasAny(normalized, ['incident response', 'reponse incident', 'containment', 'eradication', 'recovery'])) {
    return 'Workflow reponse incident: detection -> qualification -> containment -> eradication -> recovery -> retour d\'experience et ajustement des regles.';
  }

  if (hasAny(normalized, ['false positive', 'faux positif'])) {
    return 'Pour reduire les faux positifs: ajuster seuils, enrichir contexte (user/asset), ajouter exclusions ciblees et valider precision par regle.';
  }

  if (hasAny(normalized, ['mttd', 'mttr', 'kpi'])) {
    return 'KPIs SOC utiles: MTTD, MTTR, taux de faux positifs, volume par severite, et taux de cloture dans le SLA.';
  }

  if (normalized.includes('open') || normalized.includes('ouverte') || normalized.includes('ouvert')) {
    return `${counts} Pour reduire les alertes OPEN, priorisez les severites HIGH et CRITICAL puis assignez un owner SOC par alerte.`;
  }

  if (
    normalized.includes('db') ||
    normalized.includes('database') ||
    normalized.includes('mongo') ||
    normalized.includes('base de donne')
  ) {
    return `${counts} Cote base de donnees, surveillez la latence des requetes, indexez les champs de filtre frequents et verifiez MONGO_URI/etat de connexion.`;
  }

  if (normalized.includes('security') || normalized.includes('securite') || normalized.includes('alert') || normalized.includes('incident')) {
    return `${counts} Recommandation securite: valider les regles de detection, corriger les faux positifs et suivre MTTD/MTTR dans le dashboard.`;
  }

  if (reason === 'missing_api_key') {
    return 'Mode local actif: la cle GEMINI_API_KEY est absente sur le serveur.';
  }

  if (hasAny(normalized, ['security', 'securite', 'threat', 'incident', 'malware', 'attack', 'attaque'])) {
    if (topic && SECURITY_TOPIC_GUIDANCE[topic]) {
      return SECURITY_TOPIC_GUIDANCE[topic];
    }
    return formatSecurityTip(context);
  }

  return pickByMode(
    mode,
    'Je peux repondre. Pose la question en une phrase claire.',
    'Je peux repondre sur le sujet de ton choix. Donne juste le theme exact.',
    'Je peux repondre sur n\'importe quel sujet. Pour une reponse plus utile, indique objectif, contexte et niveau de detail attendu.'
  );
}

function isOnTopic(message) {
  const normalized = normalizeText(message);
  return TOPIC_KEYWORDS.some((kw) => normalized.includes(kw));
}

function extractTextFromGemini(data) {
  const text = data?.candidates?.[0]?.content?.parts
    ?.map((part) => String(part?.text || ''))
    .join('\n')
    .trim();
  return text || '';
}

async function getAlertContext() {
  const totalAlerts = await Alert.countDocuments();
  const openAlerts = await Alert.countDocuments({ alert_status: 'OPEN' });
  const investigatingAlerts = await Alert.countDocuments({ alert_status: 'INVESTIGATING' });
  const closedAlerts = await Alert.countDocuments({ alert_status: 'CLOSED' });

  return {
    totalAlerts,
    openAlerts,
    investigatingAlerts,
    closedAlerts,
  };
}

async function askAssistant(req, res) {
  try {
    const message = String(req.body?.message || '').trim();
    if (!message) {
      return res.status(400).json({ message: 'Message is required.' });
    }

    let context;
    try {
      context = await getAlertContext();
    } catch (_error) {
      context = {
        totalAlerts: 0,
        openAlerts: 0,
        investigatingAlerts: 0,
        closedAlerts: 0,
      };
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(200).json({
        reply: buildFallbackReply(message, context, 'missing_api_key'),
        fallback: true,
        provider: 'local',
        context,
      });
    }

    if (typeof fetch !== 'function') {
      return res.status(200).json({
        reply: buildFallbackReply(message, context, 'fetch_unavailable'),
        fallback: true,
        provider: 'local',
        context,
      });
    }

    const systemInstruction = [
      'You are an assistant integrated in a SOC application.',
      'Answer any user topic clearly and helpfully, in French by default.',
      'If the question is about this app, SOC, incidents, alerts, API, frontend/backend, or database, use the app context and be practical.',
      'Adapt response length to user intent: short for simple questions, detailed for procedural questions.',
      `Current app context: totalAlerts=${context.totalAlerts}, openAlerts=${context.openAlerts}, investigatingAlerts=${context.investigatingAlerts}, closedAlerts=${context.closedAlerts}.`,
    ].join(' ');

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          {
            role: 'user',
            parts: [{ text: `${systemInstruction}\n\nUser question: ${message}` }],
          },
        ],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 500,
        },
      }),
    });

    if (!response.ok) {
      return res.status(200).json({
        reply: buildFallbackReply(message, context, 'gemini_http_error'),
        fallback: true,
        provider: 'local',
        context,
      });
    }

    const data = await response.json();
    const reply = extractTextFromGemini(data);

    if (!reply) {
      return res.status(200).json({
        reply: buildFallbackReply(message, context, 'empty_gemini_response'),
        fallback: true,
        provider: 'local',
        context,
      });
    }

    return res.status(200).json({ reply, context, provider: 'gemini' });
  } catch (error) {
    return res.status(200).json({
      reply: 'Assistant local actif temporairement. Je peux repondre sur securite, alertes, incidents et base de donnees de cette application.',
      fallback: true,
      provider: 'local',
      message: error.message,
    });
  }
}

module.exports = {
  askAssistant,
};
