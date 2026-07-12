"use strict";

/* ============================================================
   web-demo.js — static, no-build browser port of the pipeline for
   the GitHub Pages demo at the repo root.

   This is a DEMO, not the source of truth. The real, tested
   implementation is the Node/CLI pipeline in src/ (see
   src/language.js, src/lexicons.js, src/classifier.js,
   src/redact.js, src/alerts.js — 58 checks in test.js). This file
   ports the same logic and the same lexicon DATA into one
   dependency-free browser script so the demo can run as a static
   page with no build step and no server. If you change the risk
   lexicons or scoring logic in src/, mirror the change here too —
   there is currently no automated check that keeps the two in
   sync, precisely because this file exists only to be a visual
   demo of what the tested Node pipeline already does.

   Detect-and-inform only, same as the CLI: this demo never blocks
   or deletes anything, and (being entirely client-side) never
   sends the text you type anywhere — everything below runs in
   your browser tab.
   ============================================================ */

(function () {

  /* ---------- language.js port ---------- */

  const SCRIPTS = [
    { lang: "ar", name: "Arabic", re: /[؀-ۿ]/ },
    { lang: "ru", name: "Russian", re: /[Ѐ-ӿ]/ },
    { lang: "hi", name: "Hindi", re: /[ऀ-ॿ]/ },
    { lang: "zh", name: "Chinese", re: /[一-鿿]/ },
    { lang: "ko", name: "Korean", re: /[가-힯]/ },
    { lang: "ja", name: "Japanese", re: /[぀-ヿ]/ },
    { lang: "he", name: "Hebrew", re: /[֐-׿]/ },
    { lang: "th", name: "Thai", re: /[฀-๿]/ },
    { lang: "el", name: "Greek", re: /[Ͱ-Ͽ]/ },
  ];

  const STOPWORDS = {
    en: ["the", "and", "you", "to", "is", "of", "in", "that", "it", "for", "are", "your", "on", "do"],
    es: ["que", "de", "la", "el", "no", "en", "y", "los", "se", "un", "por", "con", "tu", "para", "eres"],
    fr: ["le", "la", "les", "et", "de", "un", "une", "je", "tu", "ne", "pas", "est", "que", "on", "chez", "toi", "moi", "avec", "vous", "ça", "où", "ton", "ta", "suis"],
    pt: ["que", "de", "não", "o", "a", "e", "um", "uma", "você", "com", "para", "os", "eu", "tá"],
    de: ["der", "die", "das", "und", "ist", "nicht", "du", "ich", "ein", "eine", "zu", "mit", "wie", "bist"],
    it: ["che", "di", "il", "la", "e", "non", "un", "per", "con", "sono", "ti", "sei", "ho"],
  };

  const NAMES = {
    en: "English", es: "Spanish", fr: "French", pt: "Portuguese",
    de: "German", it: "Italian", und: "Undetermined",
  };

  function detectLanguage(text) {
    const s = String(text || "");
    if (s.trim() === "") return { language: "und", name: NAMES.und, confidence: 0 };

    for (const script of SCRIPTS) {
      if (script.re.test(s)) {
        return { language: script.lang, name: script.name, confidence: 0.95 };
      }
    }

    const tokens = s.toLowerCase().match(/[\p{L}']+/gu) || [];
    if (tokens.length === 0) return { language: "und", name: NAMES.und, confidence: 0 };

    const counts = {};
    for (const lang of Object.keys(STOPWORDS)) counts[lang] = 0;
    const wordSets = {};
    for (const [lang, words] of Object.entries(STOPWORDS)) wordSets[lang] = new Set(words);

    for (const tok of tokens) {
      if (tok.length < 2) continue;
      for (const lang of Object.keys(wordSets)) {
        if (wordSets[lang].has(tok)) counts[lang]++;
      }
    }

    let best = "und", bestScore = 0, total = 0;
    for (const [lang, c] of Object.entries(counts)) {
      total += c;
      if (c > bestScore) { bestScore = c; best = lang; }
    }

    if (bestScore === 0) {
      return { language: "en", name: NAMES.en, confidence: 0.3 };
    }

    const confidence = Math.min(0.95, 0.4 + (bestScore / tokens.length) * 2 + (bestScore / Math.max(total, 1)) * 0.2);
    return { language: best, name: NAMES[best] || best, confidence: Math.round(confidence * 100) / 100 };
  }

  /* ---------- lexicons.js port ---------- */

  const ANY = "any";

  const ENTRIES = [
    { category: "sexual-solicitation", langs: ["en"], weight: 0.7, re: /\b(send|show)\s+(me\s+)?(a\s+)?(pic|pics|picture|photo|photos|nude|nudes|naked)\b/i },
    { category: "sexual-solicitation", langs: ["es"], weight: 0.7, re: /\b(m[aá]nd(a|ame)|env[ií]ame|ens[eé][ñn]ame)\b.*\b(foto|fotos|desnud[oa]s?)\b/i },
    { category: "sexual-solicitation", langs: ["fr"], weight: 0.7, re: /\b(envoie|montre)(-?moi)?\b.*\b(photo|photos|nue?s?)\b/i },
    { category: "sexual-solicitation", langs: ["pt"], weight: 0.7, re: /\b(manda|envie|mostra)\b.*\b(foto|fotos|pelad[oa]s?|nu[a]?)\b/i },
    { category: "sexual-solicitation", langs: ["de"], weight: 0.7, re: /\b(schick|zeig)(\s+mir)?\b.*\b(bild|bilder|nackt|nacktbild)\b/i },
    { category: "sexual-solicitation", langs: [ANY], weight: 0.55, re: /\b(sext|sexting|horny|turn me on)\b/i },
    { category: "sexual-solicitation", langs: ["ar"], weight: 0.7, re: /صورة عارية|أرسل لي صورة/ },
    { category: "sexual-solicitation", langs: ["ru"], weight: 0.7, re: /пришли фото|голое фото/i },

    { category: "grooming", signal: "secrecy", langs: ["en"], weight: 0.5, re: /\b(don'?t|do not|never)\s+(tell|say (this|it) to|mention (this|it) to)\b[^.!?]*\b(parents?|mom|mum|dad|anyone|family)\b/i },
    { category: "grooming", signal: "secrecy", langs: ["en"], weight: 0.5, re: /\b(our|keep (it|this))\s+(little\s+)?secret\b|\bbetween (just )?us\b/i },
    { category: "grooming", signal: "secrecy", langs: ["es"], weight: 0.5, re: /\bno\s+(le\s+)?(digas|cuentes)\b[^.!?]*\b(padres|mam[aá]|pap[aá]|nadie)\b|\bnuestro secreto\b/i },
    { category: "grooming", signal: "secrecy", langs: ["fr"], weight: 0.5, re: /\bne\s+(le\s+)?dis\s+(pas|à personne|à tes parents)\b|\bnotre secret\b/i },
    { category: "grooming", signal: "secrecy", langs: ["pt"], weight: 0.5, re: /\bn[aã]o\s+(conta|fala)\b[^.!?]*\b(pais|m[aã]e|ningu[eé]m)\b|\bnosso segredo\b/i },
    { category: "grooming", signal: "secrecy", langs: ["de"], weight: 0.5, re: /\b(sag|erz[aä]hl)\s+(es\s+)?(niemandem|deinen eltern)\b|\bunser geheimnis\b/i },
    { category: "grooming", signal: "secrecy", langs: ["ar"], weight: 0.5, re: /لا تخبر والدي?ك|سرنا/ },
    { category: "grooming", signal: "secrecy", langs: ["ru"], weight: 0.5, re: /никому не говори|наш секрет/i },
    { category: "grooming", signal: "platform-move", langs: [ANY], weight: 0.5, re: /\b(add me on|let'?s (talk|chat|move) (on|to)|dm me on|do you have|text me on|hop on)\b[^.!?]*\b(snap(chat)?|telegram|whats?app|kik|discord|signal|wickr|insta(gram)?)\b/i },
    { category: "grooming", signal: "platform-move", langs: [ANY], weight: 0.45, re: /\b(pas(a|emos) a|habla?mos por|escr[ií]beme (por|en))\b[^.!?]*\b(snap|telegram|whats?app|kik)\b/i },
    { category: "grooming", signal: "meeting", langs: ["en"], weight: 0.5, re: /\b(where do you live|what'?s your address|can we meet|let'?s meet( up)?|meet up|come over|i'?ll pick you up)\b/i },
    { category: "grooming", signal: "meeting", langs: ["es"], weight: 0.5, re: /\b(d[oó]nde vives|tu direcci[oó]n|podemos vernos|nos vemos|te recojo|ven a)\b/i },
    { category: "grooming", signal: "meeting", langs: ["fr"], weight: 0.5, re: /\b(o[uù] habites[- ]tu|ton adresse|on se voit|je viens te chercher)\b/i },
    { category: "grooming", signal: "meeting", langs: ["pt"], weight: 0.5, re: /\b(onde voc[eê] mora|seu endere[çc]o|a gente se v[eê]|te busco)\b/i },
    { category: "grooming", signal: "meeting", langs: ["de"], weight: 0.5, re: /\b(wo wohnst du|deine adresse|treffen wir uns|ich hole dich ab)\b/i },
    { category: "grooming", signal: "age-probe", langs: ["en"], weight: 0.45, re: /\b(how old are you|are your parents (home|around|there)|are you (home )?alone)\b/i },
    { category: "grooming", signal: "age-probe", langs: ["es"], weight: 0.45, re: /\b(cu[aá]ntos a[nñ]os tienes|est[aá]n tus padres|est[aá]s sol[oa])\b/i },
    { category: "grooming", signal: "age-probe", langs: ["fr"], weight: 0.45, re: /\b(quel [aâ]ge as[- ]tu|tes parents sont[- ]l[aà]|tu es seul)\b/i },
    { category: "grooming", signal: "age-probe", langs: ["pt"], weight: 0.45, re: /\b(quantos anos voc[eê] tem|seus pais est[aã]o|voc[eê] est[aá] sozinh)\b/i },
    { category: "grooming", signal: "age-probe", langs: ["de"], weight: 0.45, re: /\b(wie alt bist du|sind deine eltern (da|zuhause)|bist du allein)\b/i },
    { category: "grooming", signal: "flattery", langs: ["en"], weight: 0.4, re: /\b(you'?re so mature|mature for your age|you'?re (so )?different|you'?re not like other|our little)\b/i },
    { category: "grooming", signal: "flattery", langs: ["es"], weight: 0.4, re: /\b(muy madura? para tu edad|eres diferente|no eres como)\b/i },
    { category: "grooming", signal: "enticement", langs: ["en"], weight: 0.5, re: /\b(i('| ha)ve got|i('ll| will)? (get|bring|give|hook you up with))\s+(you\s+)?(some\s+)?(drugs?|weed|pills?|molly|coke|vape|alcohol|beer|wine)\b|\b(free|some)\s+(weed|drugs?|alcohol|pills?)\s+for\s+you\b/i },
    { category: "grooming", signal: "enticement", langs: ["es"], weight: 0.5, re: /\b(tengo|te consigo|te doy|te traigo)\s+(droga|drogas|marihuana|pastillas|alcohol|cerveza)\b/i },
    { category: "grooming", signal: "enticement", langs: ["fr"], weight: 0.5, re: /\b(j'ai|je peux (t')?avoir|je t'apporte)\s+(de la |des )?(drogue|herbe|alcool|bi[eè]re)\b/i },
    { category: "grooming", signal: "enticement", langs: ["pt"], weight: 0.5, re: /\b(eu tenho|consigo|posso arranjar|te trago)\s+(droga|maconha|[aá]lcool|cerveja)\b/i },
    { category: "grooming", signal: "enticement", langs: ["de"], weight: 0.5, re: /\b(ich habe|ich besorge dir|ich bring dir)\s+(drogen|gras|alkohol|bier)\b/i },

    { category: "harassment", langs: ["en"], weight: 0.5, re: /\b(loser|freak|ugly|stupid|worthless|pathetic|nobody likes you|no one likes you|kill yourself|kys)\b/i },
    { category: "harassment", langs: ["es"], weight: 0.5, re: /\b(perdedor|fe[oa]|est[uú]pid[oa]|in[uú]til|nadie te quiere|m[aá]tate)\b/i },
    { category: "harassment", langs: ["fr"], weight: 0.5, re: /\b(rat[eé]|moche|stupide|nul|personne ne t'?aime|tue-toi)\b/i },
    { category: "harassment", langs: ["pt"], weight: 0.5, re: /\b(perdedor|fei[oa]|burr[oa]|in[uú]til|ningu[eé]m gosta de voc[eê]|se mata)\b/i },
    { category: "harassment", langs: ["de"], weight: 0.5, re: /\b(loser|h[aä]sslich|dumm|wertlos|keiner mag dich|bring dich um)\b/i },

    { category: "self-harm", langs: ["en"], weight: 0.72, re: /\b(i\s+(want|wanna)\s+to?\s+(die|kill myself)|i can'?t go on|no reason to live|end it all|i'?ve been cutting|hurt(ing)? myself|i want to disappear)\b/i },
    { category: "self-harm", langs: ["es"], weight: 0.72, re: /\b(quiero (morir(me)?|matarme)|no puedo m[aá]s|no vale la pena vivir|me hago da[nñ]o|me corto)\b/i },
    { category: "self-harm", langs: ["fr"], weight: 0.72, re: /\b(je veux mourir|je veux me tuer|je n'?en peux plus|me faire du mal|je me coupe)\b/i },
    { category: "self-harm", langs: ["pt"], weight: 0.72, re: /\b(quero morrer|quero me matar|n[aã]o aguento mais|me machuco|me corto)\b/i },
    { category: "self-harm", langs: ["de"], weight: 0.72, re: /\b(ich will sterben|ich will mich umbringen|ich kann nicht mehr|mich verletzen|ritze mich)\b/i },
    { category: "self-harm", langs: ["ar"], weight: 0.72, re: /أريد أن أموت|أريد قتل نفسي|أؤذي نفسي/ },
    { category: "self-harm", langs: ["ru"], weight: 0.72, re: /хочу умереть|убить себя|режу себя/i },
    { category: "self-harm", langs: ["hi"], weight: 0.72, re: /मैं मरना चाहता|मरना चाहती|खुद को नुकसान/ },

    { category: "violent-threat", langs: ["en"], weight: 0.72, re: /\b((i'?m (going to|gonna)|imma|ima)\s+(kill|hurt|beat)\s+(you|u|ya)(\s+up)?|i'?ll (kill|hurt|beat)\s+(you|u|ya)(\s+up)?|i will (kill|hurt|beat)\s+(you|u|ya)(\s+up)?|bring a (gun|knife)|shoot up|(you'?re|ur) dead)\b/i },
    { category: "violent-threat", langs: ["es"], weight: 0.72, re: /\b(te voy a (matar|hacer da[nñ]o|golpear)|te mato|voy a llevar (una pistola|un cuchillo))\b/i },
    { category: "violent-threat", langs: ["fr"], weight: 0.72, re: /\b(je vais te (tuer|frapper|faire du mal)|je te tue)\b/i },
    { category: "violent-threat", langs: ["pt"], weight: 0.72, re: /\b(vou te (matar|machucar|bater)|te mato)\b/i },
    { category: "violent-threat", langs: ["de"], weight: 0.72, re: /\b(ich (werde|bring) dich um|ich schlag dich (zusammen|tot))\b/i },
  ];

  const CATEGORY_LABELS = {
    "sexual-solicitation": "Sexual solicitation",
    "grooming": "Grooming pattern",
    "harassment": "Harassment / bullying",
    "self-harm": "Self-harm risk",
    "violent-threat": "Violent threat",
  };

  /* ---------- redact.js port ---------- */

  const MASK = "▇▇▇";
  const WINDOW = 22;

  function redactExcerpt(text, start, end) {
    const s = String(text || "");
    if (start == null || end == null || start < 0 || end > s.length || start >= end) {
      const head = s.slice(0, WINDOW).replace(/\s+/g, " ").trim();
      return (head ? head + " " : "") + MASK;
    }
    const from = Math.max(0, start - WINDOW);
    const to = Math.min(s.length, end + WINDOW);
    const before = s.slice(from, start).replace(/\s+/g, " ");
    const after = s.slice(end, to).replace(/\s+/g, " ");
    let excerpt = (from > 0 ? "…" : "") + before + MASK + after + (to < s.length ? "…" : "");
    excerpt = excerpt.trim();
    if (excerpt.length > 70) excerpt = excerpt.slice(0, 69).trimEnd() + "…";
    return excerpt;
  }

  /* ---------- classifier.js port ---------- */

  const MIN_CONFIDENCE = 0.45;
  const DETECT_UNSURE = 0.5;

  function noisyOr(weights) {
    return 1 - weights.reduce((p, w) => p * (1 - w), 1);
  }

  function entriesForLanguage(lang) {
    return ENTRIES.filter((e) => {
      if (e.langs.includes(ANY)) return true;
      if (e.langs.includes(lang)) return true;
      if (e.langs.includes("en")) return true;
      return false;
    });
  }

  function classify(message) {
    const text = String(message && message.text || "");
    const direction = message && message.direction === "outgoing" ? "outgoing" : "incoming";
    const relationship = (message && message.senderRelationship) || "unknown";

    const lang = detectLanguage(text);
    const unsure = lang.confidence < DETECT_UNSURE;
    const applicable = unsure ? ENTRIES : entriesForLanguage(lang.language);

    const byCategory = {};

    for (const entry of applicable) {
      if (entry.category === "self-harm" && direction !== "outgoing") continue;

      const m = entry.re.exec(text);
      if (!m) continue;

      const bucket = byCategory[entry.category] || (byCategory[entry.category] = {
        weights: [], signals: new Set(), firstStart: m.index, firstEnd: m.index + m[0].length, langHint: null,
      });
      bucket.weights.push(entry.weight);
      if (entry.signal) bucket.signals.add(entry.signal);
      if (!bucket.langHint && !entry.langs.includes(ANY) && entry.langs[0] !== "en") {
        bucket.langHint = entry.langs[0];
      }
      if (m.index < bucket.firstStart) {
        bucket.firstStart = m.index;
        bucket.firstEnd = m.index + m[0].length;
      }
    }

    const findings = [];
    for (const [category, bucket] of Object.entries(byCategory)) {
      let confidence = noisyOr(bucket.weights);

      if (category === "grooming" || category === "sexual-solicitation") {
        if (relationship === "not-mutual") confidence = noisyOr([confidence, 0.2]);
        else if (relationship === "mutual") confidence *= 0.9;
      }

      confidence = Math.min(0.99, Math.round(confidence * 100) / 100);
      if (confidence < MIN_CONFIDENCE) continue;

      const reportLang = (unsure && bucket.langHint) ? bucket.langHint : lang.language;

      findings.push({
        category,
        label: CATEGORY_LABELS[category] || category,
        confidence,
        language: reportLang,
        languageName: NAMES[reportLang] || reportLang,
        excerpt: redactExcerpt(text, bucket.firstStart, bucket.firstEnd),
        signals: [...bucket.signals],
        senderRelationship: relationship,
        direction,
      });
    }

    findings.sort((a, b) => b.confidence - a.confidence);
    return { language: lang.language, languageName: lang.name, findings };
  }

  /* ---------- alerts.js port ---------- */

  const IMMEDIATE_THRESHOLD = 0.70;

  const ACTIONS = {
    "grooming": {
      immediate: "This may need immediate attention. Review the conversation now and consider locking the app. If the contact is an unknown adult, preserve the messages and report to the platform and the NCMEC CyberTipline (report.cybertip.org).",
      review: "Borderline grooming signals. Review this conversation soon — watch for secrecy requests or pushes to move to another app.",
    },
    "sexual-solicitation": {
      immediate: "This may need immediate attention. Review the conversation, consider locking the app, and preserve the messages. Requests for images from a minor can be reported to the platform and NCMEC.",
      review: "Possible sexual content. Review the conversation with your child.",
    },
    "self-harm": {
      immediate: "This may need immediate attention. Talk with your child now and stay with them. If you believe they are in danger, contact a crisis line (in the US, call or text 988) or local emergency services.",
      review: "Your child's message shows possible distress. Check in with them soon.",
    },
    "violent-threat": {
      immediate: "Review the conversation. If the threat seems credible or imminent, contact the platform and, if there is immediate danger, local authorities. Save the messages.",
      review: "Possible threat language. Review the conversation.",
    },
    "harassment": {
      immediate: "Review the conversation with your child. Consider blocking the sender and reporting to the platform; save screenshots.",
      review: "Possible bullying. Included for your review — check in with your child.",
    },
  };

  function tierFor(confidence) {
    return confidence >= IMMEDIATE_THRESHOLD ? "immediate" : "review";
  }

  function suggestedAction(finding) {
    const perCat = ACTIONS[finding.category];
    if (!perCat) return "Review the conversation with your child.";
    return perCat[tierFor(finding.confidence)];
  }

  function contextLine(finding) {
    const rel = {
      "not-mutual": "sender: not a mutual connection",
      "mutual": "sender: mutual connection",
      "unknown": "sender relationship unknown",
    }[finding.senderRelationship] || "sender relationship unknown";
    return `"${finding.excerpt}" · ${rel}`;
  }

  function formatAlert(finding) {
    const conf = finding.confidence.toFixed(2);
    return [
      `DETECTED: ${finding.category} | ${finding.language} | ${conf}`,
      `CONTEXT: ${contextLine(finding)}`,
      `SUGGESTED ACTION: ${suggestedAction(finding)}`,
    ].join("\n");
  }

  function route(findings) {
    const immediate = [];
    const batch = [];
    for (const f of findings) {
      (f.confidence >= IMMEDIATE_THRESHOLD ? immediate : batch).push(f);
    }
    return { immediate, batch };
  }

  /* ---------- UI wiring ---------- */

  const EXAMPLES = [
    { label: "Grooming (EN)", text: "hey you're so mature for your age, don't tell your parents about this. let's talk on telegram instead", direction: "incoming", relationship: "not-mutual" },
    { label: "Sexual solicitation (ES)", text: "mándame unas fotos desnuda y no le digas a nadie", direction: "incoming", relationship: "not-mutual" },
    { label: "Self-harm (outgoing, EN)", text: "i can't go on anymore, i just want to disappear", direction: "outgoing", relationship: "unknown" },
    { label: "Violent threat (EN)", text: "i'm going to hurt you after school tomorrow", direction: "incoming", relationship: "mutual" },
    { label: "Harassment (PT)", text: "ninguém gosta de você, perdedor", direction: "incoming", relationship: "mutual" },
    { label: "Benign", text: "want to study for the math test tomorrow after practice?", direction: "incoming", relationship: "mutual" },
  ];

  function renderResult(container, result) {
    container.innerHTML = "";

    const langLine = document.createElement("div");
    langLine.className = "lang-line";
    langLine.textContent = `Detected language: ${result.languageName} (${result.language})`;
    container.appendChild(langLine);

    const { immediate, batch } = route(result.findings);

    if (immediate.length === 0 && batch.length === 0) {
      const clean = document.createElement("div");
      clean.className = "clean";
      clean.textContent = "No risk categories flagged.";
      container.appendChild(clean);
      return;
    }

    for (const f of immediate) {
      container.appendChild(renderAlertCard(f, "immediate"));
    }
    for (const f of batch) {
      container.appendChild(renderAlertCard(f, "review"));
    }
  }

  function renderAlertCard(finding, tier) {
    const card = document.createElement("pre");
    card.className = "alert-card " + (tier === "immediate" ? "tier-immediate" : "tier-review");
    card.textContent = formatAlert(finding);
    return card;
  }

  function init() {
    const textEl = document.getElementById("demo-text");
    const directionEl = document.getElementById("demo-direction");
    const relationshipEl = document.getElementById("demo-relationship");
    const resultEl = document.getElementById("demo-result");
    const formEl = document.getElementById("demo-form");
    const examplesEl = document.getElementById("demo-examples");

    if (!formEl) return; // page doesn't have the demo widget

    for (const ex of EXAMPLES) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "example-btn";
      btn.textContent = ex.label;
      btn.addEventListener("click", () => {
        textEl.value = ex.text;
        directionEl.value = ex.direction;
        relationshipEl.value = ex.relationship;
        formEl.dispatchEvent(new Event("submit"));
      });
      examplesEl.appendChild(btn);
    }

    formEl.addEventListener("submit", (e) => {
      e.preventDefault();
      const result = classify({
        text: textEl.value,
        direction: directionEl.value,
        senderRelationship: relationshipEl.value,
      });
      renderResult(resultEl, result);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Exposed for console poking / potential reuse; not required by the page.
  window.ContentRiskDemo = { classify, formatAlert, route, detectLanguage };
})();
