"use strict";

/* ============================================================
   Multilingual risk lexicons — PHASE 2.

   These are the terms/patterns the classifier matches, kept as
   DATA so the detection logic stays language-agnostic. This is a
   heuristic lexicon layer, NOT a trained model — it is deliberately
   multilingual (patterns live in each language) rather than
   translate-to-English-first, which loses the slang and coded
   language that grooming detection depends on.

   Each entry:
     category  — one of the five risk categories
     signal    — (grooming only) which grooming behaviour it is;
                 distinct signals compound into higher confidence
     langs     — languages this pattern applies to, or "any"
     weight    — 0..1 contribution, combined via noisy-OR
     re        — the pattern

   This file necessarily contains sensitive trigger terms: it is a
   safety detector and must recognise the language it protects
   against. Terms are limited to what detection requires.
   ============================================================ */

const ANY = "any";

const ENTRIES = [
  // ---------- SEXUAL SOLICITATION ----------
  { category: "sexual-solicitation", langs: ["en"], weight: 0.7, re: /\b(send|show)\s+(me\s+)?(a\s+)?(pic|pics|picture|photo|photos|nude|nudes|naked)\b/i },
  { category: "sexual-solicitation", langs: ["es"], weight: 0.7, re: /\b(m[aá]nd(a|ame)|env[ií]ame|ens[eé][ñn]ame)\b.*\b(foto|fotos|desnud[oa]s?)\b/i },
  { category: "sexual-solicitation", langs: ["fr"], weight: 0.7, re: /\b(envoie|montre)(-?moi)?\b.*\b(photo|photos|nue?s?)\b/i },
  { category: "sexual-solicitation", langs: ["pt"], weight: 0.7, re: /\b(manda|envie|mostra)\b.*\b(foto|fotos|pelad[oa]s?|nu[a]?)\b/i },
  { category: "sexual-solicitation", langs: ["de"], weight: 0.7, re: /\b(schick|zeig)(\s+mir)?\b.*\b(bild|bilder|nackt|nacktbild)\b/i },
  { category: "sexual-solicitation", langs: [ANY], weight: 0.55, re: /\b(sext|sexting|horny|turn me on)\b/i },
  { category: "sexual-solicitation", langs: ["ar"], weight: 0.7, re: /صورة عارية|أرسل لي صورة/ },
  { category: "sexual-solicitation", langs: ["ru"], weight: 0.7, re: /пришли фото|голое фото/i },

  // ---------- GROOMING (multi-signal) ----------
  // secrecy
  { category: "grooming", signal: "secrecy", langs: ["en"], weight: 0.5, re: /\b(don'?t|do not|never)\s+(tell|say (this|it) to|mention (this|it) to)\b[^.!?]*\b(parents?|mom|mum|dad|anyone|family)\b/i },
  { category: "grooming", signal: "secrecy", langs: ["en"], weight: 0.5, re: /\b(our|keep (it|this))\s+(little\s+)?secret\b|\bbetween (just )?us\b/i },
  { category: "grooming", signal: "secrecy", langs: ["es"], weight: 0.5, re: /\bno\s+(le\s+)?(digas|cuentes)\b[^.!?]*\b(padres|mam[aá]|pap[aá]|nadie)\b|\bnuestro secreto\b/i },
  { category: "grooming", signal: "secrecy", langs: ["fr"], weight: 0.5, re: /\bne\s+(le\s+)?dis\s+(pas|à personne|à tes parents)\b|\bnotre secret\b/i },
  { category: "grooming", signal: "secrecy", langs: ["pt"], weight: 0.5, re: /\bn[aã]o\s+(conta|fala)\b[^.!?]*\b(pais|m[aã]e|ningu[eé]m)\b|\bnosso segredo\b/i },
  { category: "grooming", signal: "secrecy", langs: ["de"], weight: 0.5, re: /\b(sag|erz[aä]hl)\s+(es\s+)?(niemandem|deinen eltern)\b|\bunser geheimnis\b/i },
  { category: "grooming", signal: "secrecy", langs: ["ar"], weight: 0.5, re: /لا تخبر والدي?ك|سرنا/ },
  { category: "grooming", signal: "secrecy", langs: ["ru"], weight: 0.5, re: /никому не говори|наш секрет/i },
  // platform-move (platform names are language-agnostic)
  { category: "grooming", signal: "platform-move", langs: [ANY], weight: 0.5, re: /\b(add me on|let'?s (talk|chat|move) (on|to)|dm me on|do you have|text me on|hop on)\b[^.!?]*\b(snap(chat)?|telegram|whats?app|kik|discord|signal|wickr|insta(gram)?)\b/i },
  { category: "grooming", signal: "platform-move", langs: [ANY], weight: 0.45, re: /\b(pas(a|emos) a|habla?mos por|escr[ií]beme (por|en))\b[^.!?]*\b(snap|telegram|whats?app|kik)\b/i },
  // meeting / location
  { category: "grooming", signal: "meeting", langs: ["en"], weight: 0.5, re: /\b(where do you live|what'?s your address|can we meet|let'?s meet( up)?|meet up|come over|i'?ll pick you up)\b/i },
  { category: "grooming", signal: "meeting", langs: ["es"], weight: 0.5, re: /\b(d[oó]nde vives|tu direcci[oó]n|podemos vernos|nos vemos|te recojo|ven a)\b/i },
  { category: "grooming", signal: "meeting", langs: ["fr"], weight: 0.5, re: /\b(o[uù] habites[- ]tu|ton adresse|on se voit|je viens te chercher)\b/i },
  { category: "grooming", signal: "meeting", langs: ["pt"], weight: 0.5, re: /\b(onde voc[eê] mora|seu endere[çc]o|a gente se v[eê]|te busco)\b/i },
  { category: "grooming", signal: "meeting", langs: ["de"], weight: 0.5, re: /\b(wo wohnst du|deine adresse|treffen wir uns|ich hole dich ab)\b/i },
  // age / alone probing
  { category: "grooming", signal: "age-probe", langs: ["en"], weight: 0.45, re: /\b(how old are you|are your parents (home|around|there)|are you (home )?alone)\b/i },
  { category: "grooming", signal: "age-probe", langs: ["es"], weight: 0.45, re: /\b(cu[aá]ntos a[nñ]os tienes|est[aá]n tus padres|est[aá]s sol[oa])\b/i },
  { category: "grooming", signal: "age-probe", langs: ["fr"], weight: 0.45, re: /\b(quel [aâ]ge as[- ]tu|tes parents sont[- ]l[aà]|tu es seul)\b/i },
  { category: "grooming", signal: "age-probe", langs: ["pt"], weight: 0.45, re: /\b(quantos anos voc[eê] tem|seus pais est[aã]o|voc[eê] est[aá] sozinh)\b/i },
  { category: "grooming", signal: "age-probe", langs: ["de"], weight: 0.45, re: /\b(wie alt bist du|sind deine eltern (da|zuhause)|bist du allein)\b/i },
  // flattery / trust-building from adult
  { category: "grooming", signal: "flattery", langs: ["en"], weight: 0.4, re: /\b(you'?re so mature|mature for your age|you'?re (so )?different|you'?re not like other|our little)\b/i },
  { category: "grooming", signal: "flattery", langs: ["es"], weight: 0.4, re: /\b(muy madura? para tu edad|eres diferente|no eres como)\b/i },
  // enticement (drugs/alcohol/gifts/money offered by an adult contact)
  { category: "grooming", signal: "enticement", langs: ["en"], weight: 0.5, re: /\b((i('| ha)ve got|i('ll| will)? (get|bring|give|hook you up with))\s+(you\s+)?(some\s+)?|(do you want|you want|want|wanna|try)\s+(some\s+)?)(drugs?|weed|marijuana|pills?|molly|coke|cocaine|heroin(e)?|meth|ecstasy|mdma|xanax|fentanyl|vape|alcohol|beer|wine|liquor)\b|\b(free|some)\s+(weed|drugs?|alcohol|pills?|heroin(e)?)\s+for\s+you\b/i },
  { category: "grooming", signal: "enticement", langs: ["es"], weight: 0.5, re: /\b(tengo|te consigo|te doy|te traigo)\s+(droga|drogas|marihuana|pastillas|alcohol|cerveza)\b/i },
  { category: "grooming", signal: "enticement", langs: ["fr"], weight: 0.5, re: /\b(j'ai|je peux (t')?avoir|je t'apporte)\s+(de la |des )?(drogue|herbe|alcool|bi[eè]re)\b/i },
  { category: "grooming", signal: "enticement", langs: ["pt"], weight: 0.5, re: /\b(eu tenho|consigo|posso arranjar|te trago)\s+(droga|maconha|[aá]lcool|cerveja)\b/i },
  { category: "grooming", signal: "enticement", langs: ["de"], weight: 0.5, re: /\b(ich habe|ich besorge dir|ich bring dir)\s+(drogen|gras|alkohol|bier)\b/i },

  // ---------- HARASSMENT / BULLYING ----------
  { category: "harassment", langs: ["en"], weight: 0.5, re: /\b(loser|freak|ugly|stupid|worthless|pathetic|nobody likes you|no one likes you|kill yourself|kys)\b/i },
  { category: "harassment", langs: ["es"], weight: 0.5, re: /\b(perdedor|fe[oa]|est[uú]pid[oa]|in[uú]til|nadie te quiere|m[aá]tate)\b/i },
  { category: "harassment", langs: ["fr"], weight: 0.5, re: /\b(rat[eé]|moche|stupide|nul|personne ne t'?aime|tue-toi)\b/i },
  { category: "harassment", langs: ["pt"], weight: 0.5, re: /\b(perdedor|fei[oa]|burr[oa]|in[uú]til|ningu[eé]m gosta de voc[eê]|se mata)\b/i },
  { category: "harassment", langs: ["de"], weight: 0.5, re: /\b(loser|h[aä]sslich|dumm|wertlos|keiner mag dich|bring dich um)\b/i },

  // ---------- SELF-HARM (child's OUTGOING only; gated in classifier) ----------
  // Weighted high: a self-harm disclosure is acute and should alert immediately.
  { category: "self-harm", langs: ["en"], weight: 0.72, re: /\b(i\s+(want|wanna)\s+to?\s+(die|kill myself)|i can'?t go on|no reason to live|end it all|i'?ve been cutting|hurt(ing)? myself|i want to disappear)\b/i },
  { category: "self-harm", langs: ["es"], weight: 0.72, re: /\b(quiero (morir(me)?|matarme)|no puedo m[aá]s|no vale la pena vivir|me hago da[nñ]o|me corto)\b/i },
  { category: "self-harm", langs: ["fr"], weight: 0.72, re: /\b(je veux mourir|je veux me tuer|je n'?en peux plus|me faire du mal|je me coupe)\b/i },
  { category: "self-harm", langs: ["pt"], weight: 0.72, re: /\b(quero morrer|quero me matar|n[aã]o aguento mais|me machuco|me corto)\b/i },
  { category: "self-harm", langs: ["de"], weight: 0.72, re: /\b(ich will sterben|ich will mich umbringen|ich kann nicht mehr|mich verletzen|ritze mich)\b/i },
  { category: "self-harm", langs: ["ar"], weight: 0.72, re: /أريد أن أموت|أريد قتل نفسي|أؤذي نفسي/ },
  { category: "self-harm", langs: ["ru"], weight: 0.72, re: /хочу умереть|убить себя|режу себя/i },
  { category: "self-harm", langs: ["hi"], weight: 0.72, re: /मैं मरना चाहता|मरना चाहती|खुद को नुकसान/ },

  // ---------- VIOLENT THREATS ----------
  { category: "violent-threat", langs: ["en"], weight: 0.72, re: /\b((i'?m (going to|gonna)|imma|ima)\s+(kill|hurt|beat)\s+(you|u|ya)(\s+up)?|i'?ll (kill|hurt|beat)\s+(you|u|ya)(\s+up)?|i will (kill|hurt|beat)\s+(you|u|ya)(\s+up)?|bring a (gun|knife)|shoot up|(you'?re|ur) dead)\b/i },
  { category: "violent-threat", langs: ["es"], weight: 0.72, re: /\b(te voy a (matar|hacer da[nñ]o|golpear)|te mato|voy a llevar (una pistola|un cuchillo))\b/i },
  { category: "violent-threat", langs: ["fr"], weight: 0.72, re: /\b(je vais te (tuer|frapper|faire du mal)|je te tue)\b/i },
  { category: "violent-threat", langs: ["pt"], weight: 0.72, re: /\b(vou te (matar|machucar|bater)|te mato)\b/i },
  { category: "violent-threat", langs: ["de"], weight: 0.72, re: /\b(ich (werde|bring) dich um|ich schlag dich (zusammen|tot))\b/i },
];

const CATEGORIES = [
  "sexual-solicitation",
  "grooming",
  "harassment",
  "self-harm",
  "violent-threat",
];

// Human-readable category labels for alerts.
const CATEGORY_LABELS = {
  "sexual-solicitation": "Sexual solicitation",
  "grooming": "Grooming pattern",
  "harassment": "Harassment / bullying",
  "self-harm": "Self-harm risk",
  "violent-threat": "Violent threat",
};

module.exports = { ENTRIES, CATEGORIES, CATEGORY_LABELS, ANY };
