// Client-side AI / NLP Heuristic & Bayesian-Weighted Spam & Cyber Fraud Detector
(function (global) {
  const SG = (global.SentinelGrid = global.SentinelGrid || {});

  const SPAM_SAMPLES = {
    kyc: {
      channel: 'sms',
      sender: 'ALERT-BANK-KYC <verify@hdfc-kyc-update.xyz>',
      text: 'URGENT NOTICE: Your bank account will be SUSPENDED within 24 hours due to incomplete KYC verification! Click immediately to verify your OTP and PAN details or face legal action: http://bit.ly/3xKycVerifyNow'
    },
    crypto: {
      channel: 'whatsapp',
      sender: '+44 7911 882104 (Unknown)',
      text: 'CONGRATULATIONS!! You have been selected for our Exclusive Crypto Airdrop Giveaway! Send 0.05 ETH or connect your wallet to receive 2.5 ETH guaranteed returns in 10 minutes. Limited slots! Claim reward here: https://eth-bonus-claim.top/airdrop'
    },
    job: {
      channel: 'whatsapp',
      sender: 'HR Recruiter Sarah',
      text: 'Hello! I am Sarah from Global Remote Recruitment. Earn $350-$600 daily liking YouTube videos from home, no experience needed. To activate your VIP task account, please pay a refundable registration deposit via Telegram @hr_fastpay_bot.'
    },
    parcel: {
      channel: 'sms',
      sender: 'USPS-Track',
      text: 'Your package #US99281 could not be delivered due to an unpaid customs fee of $2.99. Confirm your home address and card CVV within 12 hours to avoid return: https://usps-redelivery-fee.click/pay'
    },
    safe: {
      channel: 'email',
      sender: 'maya.patel@acmecorp.com',
      text: 'Hi team, quick reminder that our weekly security review is moved to Thursday at 2:00 PM in Conference Room B. Please review the agenda in our shared workspace before the meeting. Thanks, Maya!'
    }
  };

  const BRAND_LOOKALIKES = [
    { brand: 'paypal', pattern: /paypa[1l]|p[a@]ypal-?(verify|secure|login)/i },
    { brand: 'amazon', pattern: /arnazon|amaz0n|amazon-?(security|refund|prime-verify)/i },
    { brand: 'microsoft', pattern: /micros0ft|rnicrosoft|microsoft-?(support|login-alert)/i },
    { brand: 'google', pattern: /g00gle|goog1e|google-?(security-alert|verify)/i },
    { brand: 'apple', pattern: /app1e|apple-?(id-locked|support-verify)/i },
    { brand: 'bank/upi', pattern: /(hdfc|sbi|icici|chase|wells|boa|citi|upi)[-_]?(kyc|verify|update|secure|help)/i }
  ];

  const SHORTENERS = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|rb\.gy|is\.gd|cutt\.ly|ow\.ly|shorturl\.at)/i;
  const RISKY_TLDS = /\.(xyz|top|tk|ml|ga|cf|gq|click|icu|vip|buzz|work|loan|rest)\b/i;

  const RULES = [
    {
      category: 'urgency',
      label: 'Urgency & Fear Pressure',
      weight: 22,
      severity: 'high',
      regex: /\b(urgent|immediately|within \d+ (?:hour|hours|minute|minutes)|suspended|blocked|terminated|legal action|arrest warrant|final notice|last warning|act now|expires today|account locked)\b/gi,
      reason: 'Uses artificial time pressure or fear of penalty to rush you into acting without verifying.'
    },
    {
      category: 'credentials',
      label: 'Credential / OTP / KYC Theft',
      weight: 28,
      severity: 'high',
      regex: /\b(share (?:your )?otp|verify (?:your )?(?:kyc|account|identity)|cvv|pin number|pan card|ssn|seed phrase|recovery phrase|connect (?:your )?wallet|password reset|bank details|card number)\b/gi,
      reason: 'Requests sensitive authentication codes, KYC documents, wallet keys, or payment credentials.'
    },
    {
      category: 'financial',
      label: 'Financial Lure / Advance-Fee',
      weight: 24,
      severity: 'high',
      regex: /\b(congratulations|you (?:have )?won|guaranteed returns|double your|airdrop|claim (?:your )?(?:reward|prize)|refundable deposit|registration fee|customs fee|earn \$\d+|daily income|easy money|gift card|wire transfer)\b/gi,
      reason: 'Promises unrealistic rewards, easy remote income, or demands a small upfront fee/deposit.'
    },
    {
      category: 'impersonation',
      label: 'Authority / Brand Impersonation',
      weight: 18,
      severity: 'warn',
      regex: /\b(irs|tax department|customs officer|cyber police|tech support|customer care|fraud department|hr recruiter|usps|fedex|dhl|official notice)\b/gi,
      reason: 'Claims to represent an official institution, bank, delivery service, or recruiter.'
    },
    {
      category: 'offplatform',
      label: 'Off-Platform Migration',
      weight: 14,
      severity: 'warn',
      regex: /\b(telegram|whatsapp me|dm me on|click (?:the )?link below|kindly click|reply with yes)\b|@[a-z0-9_]{4,}_bot\b/gi,
      reason: 'Pushes communication onto encrypted/unmonitored channels or automated bots to evade platform filters.'
    }
  ];

  function redactPII(text) {
    if (!text) return '';
    return text
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
      .replace(/(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g, '[REDACTED_PHONE]')
      .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[REDACTED_CARD]')
      .replace(/\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk-[a-zA-Z0-9]{20,})\b/g, '[REDACTED_KEY]');
  }

  function extractUrls(text) {
    const matches = text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
    return [...new Set(matches)];
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function buildHighlightedHtml(text, ranges) {
    if (!ranges.length) return escapeHtml(text);
    const sorted = [...ranges].sort((a, b) => a.start - b.start);
    const merged = [];
    for (const r of sorted) {
      const prev = merged[merged.length - 1];
      if (prev && r.start <= prev.end) {
        prev.end = Math.max(prev.end, r.end);
        if (r.severity === 'high') prev.severity = 'high';
      } else {
        merged.push({ ...r });
      }
    }

    let out = '';
    let cursor = 0;
    for (const r of merged) {
      if (r.start > cursor) {
        out += escapeHtml(text.slice(cursor, r.start));
      }
      const cls = r.severity === 'high' ? 'trig-high' : 'trig-warn';
      out += `<mark class="${cls}">${escapeHtml(text.slice(r.start, r.end))}</mark>`;
      cursor = r.end;
    }
    if (cursor < text.length) {
      out += escapeHtml(text.slice(cursor));
    }
    return out;
  }

  function buildAdvice({ riskScore, scores, urls, channel }) {
    if (riskScore < 20) {
      return [
        'No major fraud patterns detected, though you should still avoid sharing sensitive credentials unexpectedly.',
        'If the sender asks for money or account changes later, verify via an independent phone number or official app.'
      ];
    }

    const tips = [
      'Do NOT click any links, download attachments, or reply to this sender.',
      'Block the sender and mark the message as spam/phishing inside your ' + channel.toUpperCase() + ' app.'
    ];

    if (scores.credentials >= 25) {
      tips.push('Never share OTPs, PINs, CVVs, or wallet seed phrases—legitimate banks and agencies never ask for them via message.');
    }
    if (scores.financial >= 25) {
      tips.push('Never pay an upfront "customs", "registration", or "unlock" fee to receive a prize, parcel, or job.');
    }
    if (urls.length > 0) {
      tips.push('Open your bank or service manually by typing the official website address or using its official mobile app.');
    }
    if (riskScore >= 60) {
      tips.push('If you already clicked the link or shared an OTP, immediately freeze your card/account, change passwords, and call your local cybercrime helpline.');
    }
    return tips;
  }

  function analyzeSpamMessage({ text, sender = '', channel = 'sms' }) {
    const cleanText = (text || '').trim();
    const scores = {
      urgency: 0,
      credentials: 0,
      financial: 0,
      impersonation: 0,
      linkRisk: 0,
      obfuscation: 0
    };

    const findings = [];
    const highlightRanges = [];

    for (const rule of RULES) {
      const matches = [...cleanText.matchAll(rule.regex)];
      if (matches.length > 0) {
        const catKey = rule.category === 'offplatform' ? 'impersonation' : rule.category;
        const boost = Math.min(100, rule.weight + (matches.length - 1) * 8);
        scores[catKey] = Math.min(100, scores[catKey] + boost);
        const uniqueHits = [...new Set(matches.map(m => m[0]))].slice(0, 4);
        findings.push({
          severity: rule.severity,
          title: rule.label,
          detail: `${rule.reason} Matched: ${uniqueHits.map(t => `"${t}"`).join(', ')}.`
        });
        for (const m of matches) {
          highlightRanges.push({
            start: m.index,
            end: m.index + m[0].length,
            severity: rule.severity
          });
        }
      }
    }

    const urls = extractUrls(cleanText);
    for (const rawUrl of urls) {
      const idx = cleanText.indexOf(rawUrl);
      let urlSuspicious = false;

      if (/^http:\/\//i.test(rawUrl)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 22);
        findings.push({ severity: 'warn', title: 'Unencrypted HTTP Link', detail: `Link uses unencrypted HTTP (${rawUrl}).` });
        urlSuspicious = true;
      }
      if (SHORTENERS.test(rawUrl)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 38);
        findings.push({ severity: 'high', title: 'Obfuscated URL Shortener', detail: `Shortened URL hides true destination: ${rawUrl}.` });
        urlSuspicious = true;
      }
      if (RISKY_TLDS.test(rawUrl)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 34);
        findings.push({ severity: 'high', title: 'High-Risk Disposable TLD', detail: `Domain uses a TLD frequently abused in phishing campaigns (${rawUrl}).` });
        urlSuspicious = true;
      }
      if (/https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i.test(rawUrl)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 45);
        findings.push({ severity: 'high', title: 'Raw IP Address URL', detail: `Link points directly to an IP address instead of a verified domain: ${rawUrl}.` });
        urlSuspicious = true;
      }
      if (/xn--/i.test(rawUrl)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 42);
        findings.push({ severity: 'high', title: 'Punycode / IDN Homograph Risk', detail: 'Domain contains punycode ("xn--") often used for lookalike character spoofing.' });
        urlSuspicious = true;
      }
      for (const b of BRAND_LOOKALIKES) {
        if (b.pattern.test(rawUrl)) {
          scores.linkRisk = Math.min(100, scores.linkRisk + 50);
          findings.push({ severity: 'high', title: `Lookalike Domain Spoofing (${b.brand})`, detail: `URL impersonates "${b.brand}" using deceptive characters or hyphenated domains.` });
          urlSuspicious = true;
        }
      }

      if (urlSuspicious && idx !== -1) {
        highlightRanges.push({ start: idx, end: idx + rawUrl.length, severity: 'high' });
      }
    }

    if (sender.trim()) {
      for (const b of BRAND_LOOKALIKES) {
        if (b.pattern.test(sender)) {
          scores.impersonation = Math.min(100, scores.impersonation + 40);
          findings.push({
            severity: 'high',
            title: 'Suspicious Sender Domain',
            detail: `Sender "${sender}" resembles brand "${b.brand}" on a non-official domain.`
          });
        }
      }
      if (RISKY_TLDS.test(sender)) {
        scores.linkRisk = Math.min(100, scores.linkRisk + 25);
        findings.push({
          severity: 'warn',
          title: 'Disposable Sender TLD',
          detail: `Sender address uses a high-risk TLD (${sender}).`
        });
      }
      if (/\b(bank|support|security|admin|kyc|paypal|amazon)\b/i.test(sender) && /@(gmail|yahoo|outlook|hotmail)\.com/i.test(sender)) {
        scores.impersonation = Math.min(100, scores.impersonation + 42);
        findings.push({
          severity: 'high',
          title: 'Official Brand Using Free Webmail',
          detail: `Sender claims to be official support/bank while emailing from a free consumer domain (${sender}).`
        });
      }
    }

    const zeroWidthMatches = cleanText.match(/[\u200B-\u200D\uFEFF]/g);
    if (zeroWidthMatches) {
      scores.obfuscation = Math.min(100, scores.obfuscation + 45);
      findings.push({
        severity: 'high',
        title: 'Hidden Zero-Width Unicode Characters',
        detail: `Detected ${zeroWidthMatches.length} invisible characters used to bypass spam filters.`
      });
    }
    const letters = cleanText.replace(/[^a-zA-Z]/g, '');
    const upperLetters = cleanText.replace(/[^A-Z]/g, '');
    if (letters.length > 20 && upperLetters.length / letters.length > 0.35) {
      scores.obfuscation = Math.min(100, scores.obfuscation + 22);
      findings.push({
        severity: 'warn',
        title: 'Excessive All-Caps Shouting',
        detail: 'High proportion of uppercase letters typical of automated scam blasts.'
      });
    }
    if ((cleanText.match(/!{2,}|\${2,}/g) || []).length > 0) {
      scores.obfuscation = Math.min(100, scores.obfuscation + 18);
    }

    const weightedSum =
      scores.credentials * 0.27 +
      scores.urgency * 0.21 +
      scores.financial * 0.20 +
      scores.linkRisk * 0.18 +
      scores.impersonation * 0.09 +
      scores.obfuscation * 0.05;

    const activeSignals = Object.values(scores).filter(v => v >= 20).length;
    const synergyBonus = activeSignals >= 3 ? 18 : activeSignals === 2 ? 9 : 0;
    const maxSignal = Math.max(...Object.values(scores));
    const riskScore = Math.min(100, Math.round(Math.max(weightedSum + synergyBonus, maxSignal * 0.72)));

    let verdict = 'Likely Safe';
    let verdictTone = 'safe';
    if (riskScore >= 72) {
      verdict = 'Critical Scam / Phishing';
      verdictTone = 'danger';
    } else if (riskScore >= 45) {
      verdict = 'High-Risk Spam / Fraud';
      verdictTone = 'danger';
    } else if (riskScore >= 20) {
      verdict = 'Suspicious — Verify Sender';
      verdictTone = 'warn';
    }

    let scamType = 'Clean / Benign';
    if (riskScore >= 20) {
      if (scores.credentials >= 30 && (scores.urgency >= 20 || scores.impersonation >= 20)) {
        scamType = 'Account / KYC Phishing';
      } else if (scores.financial >= 30) {
        scamType = 'Financial / Crypto / Job Scam';
      } else if (scores.linkRisk >= 35) {
        scamType = 'Malicious Link / Smishing';
      } else if (scores.urgency >= 25) {
        scamType = 'Social Engineering Pressure';
      } else {
        scamType = 'Unsolicited Spam';
      }
    }

    const confidence = Math.min(98, Math.max(62, 65 + findings.length * 6 + (urls.length > 0 ? 5 : 0)));

    return {
      riskScore,
      verdict,
      verdictTone,
      scamType,
      confidence,
      linkCount: urls.length,
      urls,
      scores,
      findings,
      advice: buildAdvice({ riskScore, scores, urls, channel }),
      highlightedHtml: buildHighlightedHtml(cleanText, highlightRanges),
      redactedPreview: redactPII(cleanText)
    };
  }

  SG.SPAM_SAMPLES = SPAM_SAMPLES;
  SG.redactPII = redactPII;
  SG.escapeHtml = escapeHtml;
  SG.analyzeSpamMessage = analyzeSpamMessage;
})(window);
