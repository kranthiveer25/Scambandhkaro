/**
 * ScamBandhKaro - AI Scam Detection Engine
 * Smart rule-based ML system for detecting scams
 * No external API required - runs entirely in browser
 */

const ScamDetector = (() => {

  // ─── SHARED UTILITIES ────────────────────────────────────────────────────────

  function clamp(val, min, max) { return Math.min(max, Math.max(min, val)); }

  function scoreToRisk(score) {
    if (score >= 75) return { level: 'High Risk', color: '#ef4444', badge: 'danger' };
    if (score >= 45) return { level: 'Medium Risk', color: '#f59e0b', badge: 'warning' };
    if (score >= 20) return { level: 'Low Risk', color: '#3b82f6', badge: 'info' };
    return { level: 'Safe', color: '#10b981', badge: 'safe' };
  }

  // ─── MESSAGE DETECTOR ─────────────────────────────────────────────────────────

  const messageKeywords = {
    urgency: {
      weight: 8,
      terms: [
        // English
        'urgent', 'immediately', 'act now', 'limited time', 'expires today',
        'last chance', 'final notice', 'warning', 'alert', 'critical',
        'time sensitive', 'respond now', 'within 24 hours', 'within 2 hours',
        'account suspended', 'verify now', 'immediate action required',
        'account will be blocked', 'service will be disconnected',
        // India-specific urgency
        'kyc expired', 'kyc expire', 'kyc pending', 'kyc not done',
        'kyc update required', 'kyc verification required',
        'sim will be blocked', 'sim card deactivated', 'number will be blocked',
        'upi blocked', 'upi suspended', 'account deactivated',
        'link will expire', 'last date', 'aaj tak', 'abhi karo',
        'click now', 'click here', 'click the link', 'tap here', 'open link',
        'visit now', 'call now', 'call immediately', 'call back immediately',
        'do not ignore', 'do not delete', 'read carefully'
      ]
    },
    otp_scam: {
      weight: 14,
      terms: [
        'share otp', 'share the otp', 'send otp', 'provide otp', 'enter otp',
        'otp received', 'otp sent to your number', 'tell me the otp',
        'bata do otp', 'otp share karo', 'otp dena', 'otp bhejo',
        'one time password', 'verification code', 'share verification code',
        'i will send you a code', 'code aayega', 'code share karo',
        'do not share otp', // scammers say this to sound trustworthy then ask for it
        // standalone OTP mentions (lower match but still significant)
        ' otp ', 'your otp', 'the otp', 'otp is', 'otp ko',
        'otp number', 'enter the code', 'tell me the code'
      ]
    },
    kyc_scam: {
      weight: 13,
      terms: [
        // Compound phrases
        'kyc update', 'kyc verification', 'kyc incomplete', 'kyc not completed',
        'complete your kyc', 'aadhaar kyc', 'pan kyc', 'video kyc',
        'aadhaar linked', 'link aadhaar', 'aadhaar update', 'aadhar update',
        'pan card update', 'pan verification', 'pan link', 'pan aadhaar link',
        'update bank kyc', 'bank account kyc', 'wallet kyc',
        're-kyc', 're kyc', 'ekyc', 'e-kyc',
        // Standalone + partial variants (cover "kyc has expired", "kyc pending", "update kyc")
        'kyc expired', 'kyc expir', 'kyc pending', 'kyc not done',
        'your kyc', 'kyc required', 'kyc is', 'kyc status',
        'kyc process', 'kyc today', 'kyc immediately',
        'update kyc', 'do kyc', 'submit kyc', 'complete kyc',
        'link below', 'click the link', 'click here to', 'verify now',
        // Aadhaar standalone variants
        'aadhaar number', 'aadhar number', 'aadhaar verify', 'aadhaar link',
        'update aadhaar', 'aadhaar expired', 'aadhaar blocked'
      ]
    },
    upi_payment: {
      weight: 12,
      terms: [
        'upi', 'gpay', 'google pay', 'phonepe', 'phone pe', 'paytm',
        'bhim', 'bhim upi', 'neft', 'imps', 'rtgs',
        'scan qr', 'qr code', 'scan and pay', 'payment link', 'pay link',
        'send ₹', 'transfer ₹', 'send rs', 'transfer rs',
        'cashback offer', 'cashback credited', 'reward points',
        'collect payment', 'request money', 'money request',
        'pay processing fee', 'pay registration fee', 'refundable deposit',
        'wallet recharge', 'recharge now'
      ]
    },
    financial: {
      weight: 10,
      terms: [
        // Global
        'wire transfer', 'gift card', 'bitcoin', 'crypto', 'cryptocurrency',
        'send money', 'payment required', 'processing fee', 'lottery',
        'prize money', 'inheritance', 'free money', 'cash reward',
        'unclaimed funds', 'refund', 'overpayment', 'google play card',
        'western union', 'moneygram',
        // India-specific financial fraud
        'instant loan', 'quick loan', 'easy loan', 'pre-approved loan',
        'no cibil check', 'bad cibil', 'cibil score', 'loan approved',
        'emi waiver', 'loan waived', 'insurance claim',
        'guaranteed returns', '10x returns', 'double your money',
        'stock tips', 'sure shot tips', 'intraday tips', 'trading tips',
        'sebi registered', 'sebi approved expert', 'forex trading',
        'mutual fund returns', 'high returns guaranteed',
        'earn daily', 'earn weekly', 'earn ₹', 'earn rs',
        'youtube task', 'instagram task', 'task complete',
        'daily earning', 'weekly payout', 'part time earning',
        'pm kisan', 'pm awas', 'government subsidy', 'subsidy amount',
        'electricity subsidy', 'gas subsidy', 'ration card benefit',
        'kisan samman', 'scholarship amount', 'bpl benefits'
      ]
    },
    threats: {
      weight: 12,
      terms: [
        // Global
        'arrest', 'lawsuit', 'legal action', 'penalty', 'warrant',
        'court', 'debt collector', 'overdue', 'suspended', 'terminated',
        'hacked', 'compromised', 'virus detected', 'malware', 'blocked',
        // India-specific threats
        'cyber police', 'cyber crime', 'cybercrime notice', 'cybercrime case',
        'cbi notice', 'cbi officer', 'cbi investigation', 'cbi case',
        'ed notice', 'enforcement directorate', 'ed officer',
        'income tax notice', 'it department notice', 'tax evasion', 'income tax raid',
        'money laundering', 'hawala', 'benami transaction',
        'ncb', 'narcotics', 'drug parcel', 'illegal parcel', 'drug case',
        'customs department', 'parcel held at customs', 'illegal package',
        'trai notice', 'sim deactivation notice',
        'fir registered', 'fir filed', 'fir against you', 'warrant issued', 'warrant in your name',
        'jail', 'giraftari', 'police aayi', 'case darj', 'arrest warrant',
        'criminal case', 'criminal activity', 'criminal complaint',
        'your aadhaar is used', 'aadhaar used in crime', 'aadhaar linked to crime',
        'linked to crime', 'linked to fraud', 'linked to illegal',
        'account used for fraud', 'account used in crime'
      ]
    },
    personalInfo: {
      weight: 11,
      terms: [
        // Global
        'credit card number', 'bank details', 'account number',
        'password', 'pin number', 'date of birth',
        'verify your identity', 'confirm your details', 'enter your credentials',
        // India-specific
        'aadhaar number', 'aadhar number', 'aadhaar card number',
        'pan number', 'pan card number',
        'cvv', 'card cvv', 'atm pin', 'debit card pin', 'atm card number',
        'net banking password', 'net banking id', 'internet banking',
        'upi pin', 'upi id', 'vpa', 'virtual payment address',
        'bank account number', 'ifsc code',
        'date of birth verification', 'mother name', 'nominee details',
        'voter id', 'driving licence number', 'passport number',
        'biometric', 'fingerprint verification'
      ]
    },
    prizes: {
      weight: 8,
      terms: [
        // Global
        'congratulations', 'lucky winner', 'you won', 'claim your prize',
        'sweepstakes', 'you are our winner', 'claim now', 'redeem',
        // India-specific prize scams
        'kaun banega crorepati', 'kbc lottery', 'kbc winner',
        'flipkart lucky draw', 'amazon lucky draw', 'amazon spin and win',
        'jio lucky draw', 'airtel lucky draw', 'sim lucky draw',
        'you have won ₹', 'you have won rs', 'lucky number selected',
        'bumper prize', 'first prize winner', 'mega jackpot',
        'coupon code winner', 'scratch card winner'
      ]
    },
    job_scam: {
      weight: 11,
      terms: [
        'work from home', 'wfh job', 'work from home job',
        'part time job', 'part-time earning', 'data entry job',
        'youtube like and earn', 'youtube subscribe earn',
        'instagram follow and earn', 'telegram task',
        'like subscribe share earn', 'task based earning',
        'online earning', 'ghar baithe kamao', 'ghar se kaam',
        'daily task payout', 'per task payment',
        'no investment required', 'zero investment business',
        'registration fee for job', 'security deposit for job',
        'training fee', 'id card fee', 'joining fee',
        'mlm', 'multi level marketing', 'network marketing',
        'binary income', 'referral income unlimited'
      ]
    },
    impersonation: {
      weight: 11,
      terms: [
        // Global brands
        'amazon', 'netflix', 'apple', 'google', 'microsoft',
        'fedex', 'dhl', 'ups', 'delivery failed', 'package held',
        // Indian banks
        'sbi', 'state bank of india', 'hdfc bank', 'icici bank',
        'axis bank', 'kotak bank', 'kotak mahindra', 'pnb', 'punjab national bank',
        'bank of baroda', 'bob', 'canara bank', 'union bank', 'yes bank',
        'indusind bank', 'idfc bank', 'rbl bank',
        // Indian government
        'rbi', 'reserve bank of india', 'sebi', 'irdai',
        'income tax department', 'gst department', 'epfo',
        'aadhaar centre', 'uidai', 'nsdl', 'ndsl',
        'irctc', 'railways', 'passport seva',
        // Indian payment apps
        'paytm bank', 'phonepe support', 'gpay support',
        'google pay support', 'bhim support',
        // Indian telecom
        'jio', 'airtel', 'bsnl', 'vodafone', 'vi customer care',
        'trai', 'dot department',
        // Indian e-commerce
        'flipkart', 'meesho', 'snapdeal', 'myntra', 'nykaa',
        'swiggy', 'zomato', 'olx', 'quikr'
      ]
    }
  };

  function analyzeMessage(text) {
    if (!text || text.trim().length < 5) {
      return { error: 'Please enter a message to analyze.' };
    }

    const lower = text.toLowerCase();
    let score = 0;
    const findings = [];
    const categoryScores = {};

    // Keyword analysis
    for (const [category, data] of Object.entries(messageKeywords)) {
      const found = data.terms.filter(term => lower.includes(term));
      if (found.length > 0) {
        const catScore = Math.min(data.weight * found.length, data.weight * 2.5);
        score += catScore;
        categoryScores[category] = catScore;
        findings.push({
          type: category,
          terms: found.slice(0, 3),
          severity: data.weight >= 11 ? 'high' : 'medium'
        });
      }
    }

    // Structural analysis
    const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
    if (capsRatio > 0.4 && text.length > 20) {
      score += 10;
      findings.push({ type: 'formatting', terms: ['Excessive capital letters'], severity: 'medium' });
    }

    const urlMatches = text.match(/https?:\/\/[^\s]+/gi) || [];
    if (urlMatches.length > 0) {
      score += 10;
      findings.push({ type: 'suspicious_links', terms: [`${urlMatches.length} URL(s) detected — verify before clicking`], severity: 'medium' });
    }

    // Phone numbers in message
    const phonePattern = /(\+?91[\s-]?)?[6-9]\d{9}/g;
    const phones = text.match(phonePattern) || [];
    if (phones.length > 0) {
      score += 8;
      findings.push({ type: 'contact_extraction', terms: ['Phone number in message — do not call without verifying'], severity: 'medium' });
    }

    // Rupee amounts — often used in prize/loan/cashback scams
    const rupeePattern = /₹\s?\d|rs\.?\s?\d|inr\s?\d|\d\s?lakh|\d\s?crore/gi;
    const rupeeMatches = text.match(rupeePattern) || [];
    if (rupeeMatches.length > 0) {
      score += 10;
      findings.push({ type: 'money_mention', terms: [`${rupeeMatches.length} monetary amount(s) detected`], severity: 'medium' });
    }

    // Excessive punctuation
    const exclCount = (text.match(/!/g) || []).length;
    if (exclCount >= 3) {
      score += 6;
      findings.push({ type: 'punctuation', terms: ['Excessive exclamation marks'], severity: 'low' });
    }

    // Grammar/spelling issues
    const informalWords = (text.match(/\b(u|ur|plz|pls|asap|msg|karo|dena|bhejo|abhi)\b/gi) || []).length;
    if (informalWords >= 2) {
      score += 6;
      findings.push({ type: 'grammar', terms: ['Informal/suspicious language patterns'], severity: 'low' });
    }

    // ── COMBO BOOST ──────────────────────────────────────────────────────────
    // When multiple high-risk India-specific categories fire together, boost score
    // (real scam messages combine urgency + financial lure + threat)
    const highRiskCats = ['otp_scam','kyc_scam','upi_payment','threats','job_scam','impersonation','personalInfo'];
    const highRiskCount = findings.filter(f => highRiskCats.includes(f.type)).length;
    if (highRiskCount >= 2) {
      const boost = highRiskCount * 12;
      score += boost;
      findings.push({ type: 'multiple_scam_signals', terms: [`${highRiskCount} scam signal types combined — high-confidence scam`], severity: 'high' });
    } else if (highRiskCount === 1) {
      // One high-risk + money/urgency/suspicious link = still suspicious
      const hasBooster = findings.some(f => ['money_mention','urgency','financial','prizes','suspicious_links'].includes(f.type));
      if (hasBooster) { score += 15; }
    } else if (findings.filter(f => f.type !== 'contact_extraction').length >= 3) {
      score += 10; // General multi-signal boost
    }

    score = clamp(score, 0, 100);
    const risk = scoreToRisk(score);
    const recommendations = generateMessageRecommendations(findings, score);

    return {
      score,
      risk,
      findings,
      recommendations,
      stats: {
        wordCount: text.split(/\s+/).length,
        capsRatio: Math.round(capsRatio * 100),
        urlCount: urlMatches.length,
        categoryScores
      }
    };
  }

  function generateMessageRecommendations(findings, score) {
    const recs = [];
    const types = findings.map(f => f.type);

    if (types.includes('otp_scam'))
      recs.push('🔐 NEVER share OTP with anyone — no bank, government agency, or company will ever ask for your OTP over call or SMS.');
    if (types.includes('kyc_scam'))
      recs.push('🪪 KYC updates are done in-person at the bank/UIDAI centre or via official apps — never by clicking links in SMS/WhatsApp.');
    if (types.includes('upi_payment'))
      recs.push('💳 You do not need to scan a QR code or enter UPI PIN to receive money — only to send. Receiving requires nothing from your side.');
    if (types.includes('job_scam'))
      recs.push('💼 Legitimate jobs never ask for registration fees, security deposits, or training fees. Any such request is a scam.');
    if (types.includes('financial'))
      recs.push('🚫 Never pay a "processing fee" to receive a loan, prize, or refund. Government subsidies are never disbursed via links.');
    if (types.includes('threats'))
      recs.push('⚠️ Indian government agencies (CBI, ED, Cyber Police) never arrest or threaten via phone calls. Disconnect immediately.');
    if (types.includes('personalInfo'))
      recs.push('🔒 Never share Aadhaar number, PAN, ATM PIN, CVV, net banking password, or OTP with anyone.');
    if (types.includes('impersonation'))
      recs.push('🔍 Contact the bank/company directly using the number on their official website — not the one provided in this message.');
    if (types.includes('prizes'))
      recs.push('🎰 No legitimate lottery selects you without registration. KBC, Jio, and Amazon never announce winners via SMS/WhatsApp calls.');
    if (types.includes('suspicious_links'))
      recs.push('🔗 Do not click any links. Type the official website URL directly in your browser instead.');
    if (score >= 75)
      recs.push('🛡️ This message has multiple high-risk scam indicators. Block and report the sender immediately. Call 1930 if you\'ve already shared any details.');

    if (recs.length === 0)
      recs.push('✅ No major red flags detected, but always verify the sender\'s identity before responding or clicking any links.');
    return recs;
  }

  // ─── LINK DETECTOR ────────────────────────────────────────────────────────────

  const suspiciousTLDs = new Set([
    // Classic free/scam TLDs
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.loan', '.click', '.work',
    '.racing', '.download', '.stream', '.bid', '.win',
    '.party', '.science', '.trade', '.review',
    // Commonly abused in India
    '.online', '.site', '.website', '.space', '.fun',
    '.pw', '.cc', '.buzz', '.link', '.live',
    '.shop', '.store', '.vip', '.club', '.icu'
  ]);

  const urlShorteners = new Set([
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'tiny.cc',
    'cutt.ly', 'rb.gy', 'shorte.st', 'rebrand.ly',
    // India-specific shorteners often used in scam SMS
    'wa.me', 'whatsapp.com/send', 'forms.gle', 'linktr.ee'
  ]);

  // Global brands
  const globalBrands = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'ebay',
    'fedex', 'ups', 'dhl', 'coinbase', 'binance', 'whatsapp'
  ];

  // Indian brands — checked separately so we know the correct domain
  const indianBrands = [
    { name: 'sbi', legit: ['sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi'] },
    { name: 'hdfcbank', legit: ['hdfcbank.com'] },
    { name: 'hdfc', legit: ['hdfcbank.com', 'hdfc.com'] },
    { name: 'icicibank', legit: ['icicibank.com'] },
    { name: 'icici', legit: ['icicibank.com', 'icicidirect.com'] },
    { name: 'axisbank', legit: ['axisbank.com'] },
    { name: 'axis', legit: ['axisbank.com'] },
    { name: 'kotakbank', legit: ['kotak.com', 'kotakbank.com'] },
    { name: 'kotak', legit: ['kotak.com', 'kotakbank.com'] },
    { name: 'pnbindia', legit: ['pnbindia.in'] },
    { name: 'yesbank', legit: ['yesbank.in'] },
    { name: 'paytm', legit: ['paytm.com', 'paytmbank.com'] },
    { name: 'phonepe', legit: ['phonepe.com'] },
    { name: 'googlepay', legit: ['pay.google.com'] },
    { name: 'bhimupi', legit: ['bhimupi.org.in'] },
    { name: 'irctc', legit: ['irctc.co.in', 'irctchelp.in'] },
    { name: 'uidai', legit: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'] },
    { name: 'incometax', legit: ['incometax.gov.in', 'incometaxindiaefiling.gov.in'] },
    { name: 'gst', legit: ['gst.gov.in'] },
    { name: 'epfo', legit: ['epfindia.gov.in', 'unifiedportal-mem.epfindia.gov.in'] },
    { name: 'flipkart', legit: ['flipkart.com'] },
    { name: 'meesho', legit: ['meesho.com'] },
    { name: 'jio', legit: ['jio.com', 'jiocinema.com'] },
    { name: 'airtel', legit: ['airtel.in'] },
    { name: 'npci', legit: ['npci.org.in'] },
    { name: 'rbi', legit: ['rbi.org.in'] },
    { name: 'sebi', legit: ['sebi.gov.in'] },
  ];

  // Official Indian government domains (anything mimicking these is suspicious)
  const officialGovDomains = /\.(gov\.in|nic\.in|ernet\.in)$/;

  function analyzeLink(url) {
    if (!url || url.trim().length < 3) {
      return { error: 'Please enter a URL to analyze.' };
    }

    let cleanUrl = url.trim();
    if (!cleanUrl.match(/^https?:\/\//i)) cleanUrl = 'http://' + cleanUrl;

    let parsed;
    try {
      parsed = new URL(cleanUrl);
    } catch {
      return { error: 'Invalid URL format. Please enter a valid web address.' };
    }

    let score = 0;
    const findings = [];

    const hostname = parsed.hostname.toLowerCase();
    const tld = '.' + hostname.split('.').pop();
    const path = parsed.pathname + parsed.search;
    const subdomainCount = hostname.split('.').length - 2;

    // ── 1. TLD CHECK ──────────────────────────────────────────────────────────
    if (suspiciousTLDs.has(tld)) {
      score += 28;
      findings.push({ type: 'suspicious_tld', detail: `Suspicious top-level domain: "${tld}" — commonly used in scam websites`, severity: 'high' });
    }

    // ── 2. HTTPS CHECK ────────────────────────────────────────────────────────
    if (parsed.protocol === 'http:') {
      score += 15;
      findings.push({ type: 'no_https', detail: 'Not using HTTPS — your data could be intercepted', severity: 'medium' });
    }

    // ── 3. URL SHORTENER ──────────────────────────────────────────────────────
    if (urlShorteners.has(hostname) || urlShorteners.has(hostname + parsed.pathname.split('/')[1])) {
      score += 22;
      findings.push({ type: 'url_shortener', detail: 'Shortened URL hides the real destination — scammers use these to mask phishing links', severity: 'high' });
    }

    // ── 4. IP ADDRESS AS DOMAIN ───────────────────────────────────────────────
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      score += 40;
      findings.push({ type: 'ip_address', detail: 'Domain is a raw IP address — no legitimate bank, government, or e-commerce site uses this', severity: 'high' });
    }

    // ── 5. FAKE GOVERNMENT DOMAIN ─────────────────────────────────────────────
    // Real Indian govt sites end in .gov.in or .nic.in
    // Scam sites use: gov-in.xyz, india-gov.com, gov.in-login.site etc.
    const govKeywords = ['gov-in', 'gov.in-', 'nic-in', 'india-gov', 'govt-in',
      'incometax-india', 'aadhaar-india', 'uidai-', '-uidai', 'epfo-india',
      'irctc-login', 'gst-india', 'rbi-india', 'sebi-india'];
    const fakeGov = govKeywords.some(kw => hostname.includes(kw));
    if (fakeGov && !officialGovDomains.test(hostname)) {
      score += 45;
      findings.push({ type: 'fake_govt_domain', detail: `Fake government domain detected: "${hostname}" — real Indian govt sites end in .gov.in or .nic.in`, severity: 'high' });
    }

    // ── 6. GLOBAL BRAND TYPOSQUATTING ─────────────────────────────────────────
    let brandHit = false;
    for (const brand of globalBrands) {
      if (hostname.includes(brand)) {
        const isLegit = hostname === `${brand}.com` || hostname === `www.${brand}.com` ||
          hostname.endsWith(`.${brand}.com`);
        if (!isLegit) {
          score += 38;
          findings.push({ type: 'brand_impersonation', detail: `Possible "${brand}" impersonation: "${hostname}" is not the official domain`, severity: 'high' });
          brandHit = true; break;
        }
      }
      const obfuscated = brand.replace(/a/g, '@').replace(/o/g, '0').replace(/l/g, '1').replace(/e/g, '3').replace(/i/g, '1');
      if (obfuscated !== brand && hostname.includes(obfuscated)) {
        score += 45;
        findings.push({ type: 'character_substitution', detail: `Character substitution to fake "${brand}" — e.g. "paypa1" or "g00gle"`, severity: 'high' });
        brandHit = true; break;
      }
    }

    // ── 7. INDIAN BRAND TYPOSQUATTING ─────────────────────────────────────────
    if (!brandHit) {
      for (const brand of indianBrands) {
        if (hostname.includes(brand.name)) {
          const isLegit = brand.legit.some(d => hostname === d || hostname === `www.${d}` || hostname.endsWith(`.${d}`));
          if (!isLegit) {
            score += 40;
            findings.push({ type: 'indian_brand_impersonation', detail: `Fake "${brand.name.toUpperCase()}" site detected — official domain is ${brand.legit[0]}`, severity: 'high' });
            break;
          }
        }
      }
    }

    // ── 8. EXCESSIVE SUBDOMAINS ───────────────────────────────────────────────
    if (subdomainCount >= 3) {
      score += 18;
      findings.push({ type: 'excessive_subdomains', detail: `${subdomainCount} subdomain levels — scammers use this to show a trusted name before the real domain`, severity: 'medium' });
    }

    // ── 9. SUSPICIOUS PATH KEYWORDS ──────────────────────────────────────────
    const suspiciousPaths = [
      'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
      'banking', 'credential', 'password', 'kyc', 'otp', 'aadhaar', 'aadhar',
      'pan-verify', 'pan-update', 'upi', 'payment', 'refund', 'claim',
      'win', 'prize', 'reward', 'cashback', 'lottery'
    ];
    const pathLower = path.toLowerCase();
    const pathHits = suspiciousPaths.filter(p => pathLower.includes(p));
    if (pathHits.length >= 2) {
      score += 15;
      findings.push({ type: 'suspicious_path', detail: `Suspicious path keywords: ${pathHits.slice(0, 4).join(', ')}`, severity: 'medium' });
    }

    // ── 10. LONG URL / ENCODED CHARS ─────────────────────────────────────────
    if (url.length > 120) {
      score += 8;
      findings.push({ type: 'long_url', detail: `URL is ${url.length} characters long — may be hiding the real destination`, severity: 'low' });
    }
    const encodedCount = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedCount >= 5) {
      score += 15;
      findings.push({ type: 'url_encoding', detail: 'Heavily encoded URL characters — destination is obfuscated', severity: 'medium' });
    }

    // ── 11. NUMERIC DOMAIN ────────────────────────────────────────────────────
    const numericInDomain = (hostname.match(/\d/g) || []).length;
    if (numericInDomain >= 4) {
      score += 10;
      findings.push({ type: 'numeric_domain', detail: 'Many digits in domain name — could be auto-generated for scam use', severity: 'low' });
    }

    // ── 12. FREE HOSTING USED FOR PHISHING ───────────────────────────────────
    const freeHosts = ['000webhostapp.com', 'netlify.app', 'vercel.app', 'glitch.me',
      'web.app', 'firebaseapp.com', 'pages.dev', 'github.io', 'surge.sh'];
    if (freeHosts.some(h => hostname.endsWith(h))) {
      // Only flag if combined with suspicious path/brand
      if (pathHits.length >= 1 || score > 20) {
        score += 18;
        findings.push({ type: 'free_hosting_phishing', detail: `Hosted on free platform (${hostname}) with suspicious content — common phishing tactic`, severity: 'medium' });
      }
    }

    score = clamp(score, 0, 100);
    const risk = scoreToRisk(score);
    const recommendations = generateLinkRecommendations(findings, score, parsed);

    return {
      score,
      risk,
      findings,
      recommendations,
      stats: {
        domain: hostname,
        protocol: parsed.protocol,
        pathLength: path.length,
        hasParams: parsed.search.length > 0,
        subdomains: subdomainCount
      }
    };
  }

  function generateLinkRecommendations(findings, score, parsed) {
    const recs = [];
    const types = findings.map(f => f.type);

    if (types.includes('fake_govt_domain'))
      recs.push('🏛️ Real Indian government sites end in .gov.in or .nic.in. This is a fake government site — do not enter any details.');
    if (types.includes('indian_brand_impersonation') || types.includes('brand_impersonation') || types.includes('character_substitution'))
      recs.push('⚠️ This link is impersonating a trusted brand. Open a new tab and type the official website address directly.');
    if (types.includes('url_shortener'))
      recs.push('🔍 Never click shortened links from unknown sources. Check the real destination using a URL expander first.');
    if (types.includes('ip_address'))
      recs.push('🚫 No legitimate website uses a raw IP address. Do not open this link.');
    if (types.includes('no_https'))
      recs.push('🔒 Never enter Aadhaar, PAN, bank, or UPI details on a non-HTTPS page.');
    if (types.includes('suspicious_tld'))
      recs.push('⚠️ Free or cheap domain extensions are commonly used for scam sites. Avoid entering any personal information.');
    if (score >= 75)
      recs.push('🛡️ HIGH RISK: Do not visit this URL. Report it to cybercrime.gov.in or call 1930.');
    else if (score < 20)
      recs.push('✅ This link appears relatively safe, but always verify the site\'s identity before entering any sensitive information.');

    return recs;
  }

  // ─── PHONE DETECTOR ───────────────────────────────────────────────────────────

  const scamAreaCodes = new Set([
    '268', '284', '473', '649', '664', '767', '784', '809', '829', '849',
    '876', '900', '976', // Premium rate / Caribbean
    '246', '242', '441',
  ]);

  // +91 is India's own legitimate country code — intentionally NOT in this list
  const scamCountryCodes = new Set([
    '+92',  // Pakistan — frequently used in India-targeted scams
    '+234', // Nigeria
    '+216', // Tunisia
    '+212', // Morocco
    '+254', // Kenya
    '+256', // Uganda
    '+44',  // UK — spoofed frequently in cyber-fraud
  ]);

  function analyzePhone(phone) {
    if (!phone || phone.trim().length < 5) {
      return { error: 'Please enter a phone number to analyze.' };
    }

    const clean = phone.trim();
    const digitsOnly = clean.replace(/\D/g, '');
    let score = 0;
    const findings = [];

    // ── 1. PREMIUM RATE ──────────────────────────────────────────────────────
    if (/^(900|976)/.test(digitsOnly) || /^(\+?1)(900|976)/.test(digitsOnly)) {
      score += 50;
      findings.push({ type: 'premium_rate', detail: 'Premium-rate number — calling may incur high charges of ₹500+ per minute', severity: 'high' });
    }

    // ── 2. LENGTH VALIDATION ─────────────────────────────────────────────────
    // Valid phone numbers are 7–15 digits (ITU-T E.164 standard)
    if (digitsOnly.length < 7) {
      score += 20;
      findings.push({ type: 'invalid_length', detail: `Only ${digitsOnly.length} digits — too short to be a real phone number`, severity: 'high' });
    } else if (digitsOnly.length > 15) {
      score += 40;
      findings.push({ type: 'invalid_length', detail: `${digitsOnly.length} digits — exceeds the maximum valid phone number length (15). This is not a real phone number.`, severity: 'high' });
    } else if (digitsOnly.length >= 13 && digitsOnly.length <= 15) {
      // Unusual length — valid international format is possible but rare for India
      score += 12;
      findings.push({ type: 'unusual_length', detail: `${digitsOnly.length} digits is an unusual length — verify this is a legitimate number`, severity: 'medium' });
    }

    // ── 3. INDIAN MOBILE FORMAT CHECK ────────────────────────────────────────
    // Valid Indian local mobile: 10 digits starting with 6–9
    // Valid Indian international mobile: +91 / 91 followed by 6–9 prefix + 9 more digits
    const isValidIndianLocal = /^[6-9]\d{9}$/.test(digitsOnly);
    const isValidIndianIntl  = /^91[6-9]\d{9}$/.test(digitsOnly);
    const isValidIndian = isValidIndianLocal || isValidIndianIntl;

    if (digitsOnly.length === 10 && !isValidIndianLocal) {
      // Looks like an Indian mobile but prefix is wrong (0–5)
      score += 25;
      findings.push({ type: 'invalid_indian_format', detail: `Indian mobile numbers must start with 6, 7, 8, or 9 — this prefix (${digitsOnly[0]}) is not valid`, severity: 'high' });
    }
    if (digitsOnly.length === 12 && digitsOnly.startsWith('91') && !isValidIndianIntl) {
      score += 25;
      findings.push({ type: 'invalid_indian_format', detail: `Looks like an Indian international number (+91) but the mobile prefix is invalid`, severity: 'high' });
    }

    // ── 4. AREA CODE CHECK (US / Caribbean numbers) ───────────────────────────
    if (digitsOnly.length === 10 || (digitsOnly.length === 11 && digitsOnly[0] === '1')) {
      const areaCode = digitsOnly.length === 11 ? digitsOnly.substring(1, 4) : digitsOnly.substring(0, 3);
      if (scamAreaCodes.has(areaCode)) {
        score += 35;
        findings.push({ type: 'high_risk_area', detail: `Area code ${areaCode} is frequently associated with scam calls (Caribbean one-ring scams)`, severity: 'high' });
      }
    }

    // ── 5. SCAM COUNTRY CODES ─────────────────────────────────────────────────
    for (const code of scamCountryCodes) {
      if (clean.startsWith(code)) {
        score += 46;
        findings.push({ type: 'scam_country_code', detail: `Country code ${code} frequently appears in reported scam calls targeting India`, severity: 'medium' });
        break;
      }
    }

    // ── 6. INDIAN SCAM PATTERNS ──────────────────────────────────────────────
    // Fake IVR / robocall spoofed numbers
    if (/^1[04]\d{2,}/.test(digitsOnly)) {
      score += 20;
      findings.push({ type: 'ivr_spoofed', detail: 'Resembles an IVR or robocall number — scammers often spoof these to appear as banks or government agencies', severity: 'medium' });
    }
    // Fake toll-free (1800, 1860, 1900)
    if (/^(1800|1860|1900)\d+/.test(digitsOnly)) {
      score += 15;
      findings.push({ type: 'toll_free_spoofed', detail: 'Toll-free numbers are commonly spoofed by scammers impersonating banks or customer care', severity: 'medium' });
    }

    // ── 7. DIGIT PATTERNS ────────────────────────────────────────────────────
    // Repeating blocks (e.g. 9999999999, 1234512345)
    if (/(\d)\1{5,}/.test(digitsOnly)) {
      score += 20;
      findings.push({ type: 'repeating_digits', detail: 'Suspicious repeating digit pattern — likely a fake or test number', severity: 'medium' });
    }
    // Fully sequential (e.g. 1234567890)
    if ('01234567890123456789'.includes(digitsOnly.slice(0, 8)) ||
        '98765432109876543210'.includes(digitsOnly.slice(0, 8))) {
      score += 15;
      findings.push({ type: 'sequential_pattern', detail: 'Sequential digit pattern — this appears to be a fake number', severity: 'medium' });
    }
    // All same digit (e.g. 0000000000)
    if (/^(\d)\1+$/.test(digitsOnly)) {
      score += 30;
      findings.push({ type: 'all_same_digits', detail: 'All identical digits — clearly not a real phone number', severity: 'high' });
    }

    score = clamp(score, 0, 100);
    const risk = scoreToRisk(score);

    const recommendations = [
      score >= 75 ? '🚫 Do not call or respond to this number. Block it immediately and report it on Sanchar Saathi (sancharsaathi.gov.in).' :
        score >= 45 ? '⚠️ Exercise caution. Verify this number through official channels before calling back or sharing any details.' :
          score >= 20 ? '🔍 Some concerns found. Confirm the caller\'s identity independently before trusting this number.' :
            '✅ No significant red flags found. Still confirm the caller\'s identity before sharing personal information.'
    ];

    if (findings.some(f => f.type === 'premium_rate')) {
      recommendations.push('💰 Calling back this type of number can result in very high charges. Do not call back.');
    }
    if (findings.some(f => f.type === 'invalid_length' || f.type === 'invalid_indian_format')) {
      recommendations.push('❌ This does not appear to be a valid phone number. Do not attempt to call it.');
    }
    if (findings.some(f => f.type === 'scam_country_code')) {
      recommendations.push('🌐 Unsolicited calls from foreign country codes are a common tactic for financial and KYC scams targeting India.');
    }

    recommendations.push('📋 Report fraud calls to Sanchar Saathi (sancharsaathi.gov.in) or call 1930 (Cyber Crime Helpline).');

    return {
      score,
      risk,
      findings,
      recommendations,
      stats: {
        rawNumber: clean,
        digitsOnly,
        length: digitsOnly.length,
        hasCountryCode: clean.startsWith('+') || (digitsOnly.startsWith('91') && digitsOnly.length === 12)
      }
    };
  }

  // ─── EMAIL DETECTOR ───────────────────────────────────────────────────────────

  const disposableDomains = new Set([
    'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
    'sharklasers.com', 'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
    'spam4.me', 'trashmail.com', 'yopmail.com', 'maildrop.cc', '10minutemail.com',
    'fakeinbox.com', 'mailnull.com', 'spamgourmet.com', 'dispostable.com',
    'getairmail.com', 'mailnesia.com', 'spamfree24.org', 'trashmail.at',
    // India-popular temp mail services
    'tempr.email', 'discard.email', 'spamgrap.com', 'mailnew.com',
    'tempinbox.com', 'emailondeck.com', 'moakt.com', 'inboxkitten.com'
  ]);

  const legitimateDomains = new Set([
    'gmail.com', 'yahoo.com', 'yahoo.in', 'outlook.com', 'hotmail.com',
    'icloud.com', 'live.com', 'msn.com', 'aol.com', 'protonmail.com',
    'mail.com', 'rediffmail.com' // common in India
  ]);

  // Official Indian government email domains — anything mimicking these is a scam
  const officialGovEmailDomains = /\.(gov\.in|nic\.in|ernet\.in|ac\.in)$/;

  // Official Indian corporate email domains per brand
  const indianOfficialEmailDomains = {
    'sbi': ['sbi.co.in'],
    'hdfc': ['hdfcbank.com'],
    'icici': ['icicibank.com'],
    'axis': ['axisbank.com'],
    'kotak': ['kotak.com', 'kotakbank.com'],
    'paytm': ['paytm.com'],
    'phonepe': ['phonepe.com'],
    'irctc': ['irctc.co.in'],
    'uidai': ['uidai.gov.in'],
    'rbi': ['rbi.org.in'],
    'sebi': ['sebi.gov.in'],
    'epfo': ['epfindia.gov.in'],
    'flipkart': ['flipkart.com'],
    'amazon': ['amazon.in', 'amazon.com'],
    'jio': ['jio.com', 'ril.com'],
    'airtel': ['airtel.com', 'airtel.in'],
  };

  const suspiciousEmailKeywords = [
    'noreply', 'no-reply', 'donotreply', 'admin', 'security',
    'verify', 'alert', 'notification', 'support', 'helpdesk', 'service',
    'billing', 'account', 'update', 'confirm', 'reset', 'kyc',
    'otp', 'refund', 'prize', 'winner', 'lottery', 'claim',
    'loan', 'approve', 'approved', 'bank-alert', 'urgent',
    // India-specific additions
    'income', 'tax', 'bank', 'aadhaar', 'aadhar', 'pan',
    'subsidy', 'reward', 'cashback', 'epfo', 'pf',
    'department', 'ministry', 'government', 'govt'
  ];

  function analyzeEmail(email) {
    if (!email || !email.includes('@')) {
      return { error: 'Please enter a valid email address to analyze.' };
    }

    const clean = email.trim().toLowerCase();
    const atIndex = clean.indexOf('@');
    const localPart = clean.substring(0, atIndex);
    const domain = clean.substring(atIndex + 1);
    if (!domain) return { error: 'Invalid email format.' };

    const domainParts = domain.split('.');
    const tld = '.' + domainParts[domainParts.length - 1];
    const baseDomain = domainParts.slice(-2).join('.');

    let score = 0;
    const findings = [];

    // ── 1. DISPOSABLE EMAIL ───────────────────────────────────────────────────
    if (disposableDomains.has(domain)) {
      score += 45;
      findings.push({ type: 'disposable', detail: 'Disposable/temporary email service — no legitimate company uses these', severity: 'high' });
    }

    // ── 2. FAKE GOVERNMENT EMAIL ──────────────────────────────────────────────
    // Real Indian govt emails end in @.gov.in or @.nic.in
    const govKeywordsInDomain = ['gov-in', 'nic-in', 'gov.in.', 'india-gov',
      'incometax-india', 'uidai-', 'rbi-india', 'sebi-india', 'epfo-india'];
    const looksLikeGov = govKeywordsInDomain.some(kw => domain.includes(kw));
    if (looksLikeGov && !officialGovEmailDomains.test(domain)) {
      score += 50;
      findings.push({ type: 'fake_govt_email', detail: `Fake government email domain: "${domain}" — official Indian govt emails end in @xyz.gov.in or @xyz.nic.in`, severity: 'high' });
    }

    // ── 3. INDIAN BRAND IMPERSONATION ─────────────────────────────────────────
    let brandImpersonated = false;
    for (const [brand, officialDomains] of Object.entries(indianOfficialEmailDomains)) {
      if (domain.includes(brand) && !officialDomains.includes(domain)) {
        score += 40;
        findings.push({ type: 'indian_brand_impersonation', detail: `Fake "${brand.toUpperCase()}" email — official emails come from @${officialDomains[0]} only`, severity: 'high' });
        brandImpersonated = true; break;
      }
    }

    // ── 4. GLOBAL BRAND TYPOSQUATTING ─────────────────────────────────────────
    if (!brandImpersonated) {
      for (const brand of globalBrands) {
        if (domain.includes(brand) && !legitimateDomains.has(domain)) {
          const officialDomains = [`${brand}.com`, `${brand}.org`, `${brand}.net`, `${brand}.in`];
          if (!officialDomains.includes(baseDomain)) {
            score += 38;
            findings.push({ type: 'brand_impersonation', detail: `Domain impersonates "${brand}" — "${domain}" is not their official email domain`, severity: 'high' });
            break;
          }
        }
        // Character substitution check
        const obfuscated = brand.replace(/a/g, '@').replace(/o/g, '0').replace(/l/g, '1').replace(/e/g, '3');
        if (obfuscated !== brand && domain.includes(obfuscated)) {
          score += 45;
          findings.push({ type: 'character_substitution', detail: `Character substitution to fake "${brand}" in email domain`, severity: 'high' });
          break;
        }
      }
    }

    // ── 5. SUSPICIOUS TLD ─────────────────────────────────────────────────────
    if (suspiciousTLDs.has(tld)) {
      score += 28;
      findings.push({ type: 'suspicious_tld', detail: `Suspicious email TLD: "${tld}" — commonly used for phishing`, severity: 'high' });
    }

    // ── 6. NUMBERS IN DOMAIN ──────────────────────────────────────────────────
    const numericInDomain = (baseDomain.match(/\d/g) || []).length;
    if (numericInDomain >= 3 && !legitimateDomains.has(domain)) {
      score += 15;
      findings.push({ type: 'numeric_domain', detail: 'Unusual numbers in email domain — may be auto-generated for spam', severity: 'medium' });
    }

    // ── 7. SUSPICIOUS LOCAL PART ──────────────────────────────────────────────
    const localHits = suspiciousEmailKeywords.filter(kw => localPart.includes(kw));
    if (localHits.length >= 2) {
      score += 15;
      findings.push({ type: 'suspicious_local', detail: `Suspicious sender prefix keywords: "${localHits.slice(0, 3).join('", "')}"`, severity: 'medium' });
    } else if (localHits.length === 1 && score > 10) {
      score += 8;
      findings.push({ type: 'suspicious_local', detail: `Suspicious keyword in sender name: "${localHits[0]}"`, severity: 'low' });
    }

    // ── 8. HYPHEN-HEAVY DOMAIN ────────────────────────────────────────────────
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 12;
      findings.push({ type: 'hyphenated_domain', detail: `Domain has ${hyphenCount} hyphens — scam domains often string words together with hyphens`, severity: 'medium' });
    }

    // ── 9. VERY LONG LOCAL PART ───────────────────────────────────────────────
    if (localPart.length > 30) {
      score += 8;
      findings.push({ type: 'long_local', detail: 'Unusually long sender name — auto-generated scam address pattern', severity: 'low' });
    }

    // ── 10. MANY DIGITS IN LOCAL PART ────────────────────────────────────────
    const localNums = (localPart.match(/\d/g) || []).length;
    if (localNums >= 5) {
      score += 10;
      findings.push({ type: 'numeric_local', detail: `${localNums} digits in sender name — common auto-generated scam address pattern (e.g. sbi.alert82736@...)`, severity: 'low' });
    }

    // ── 11. FREE DOMAIN USED FOR OFFICIAL-SOUNDING SENDER ────────────────────
    if (legitimateDomains.has(domain)) {
      if (localHits.length >= 2) {
        score += 32;
        findings.push({ type: 'free_email_official_impersonation', detail: `Official-sounding sender from free email provider (${domain}) — banks, UIDAI, Income Tax, and government departments NEVER email from Gmail/Yahoo/Rediff`, severity: 'high' });
      } else if (localHits.length === 1) {
        // Even one suspicious keyword from a free provider is a red flag
        score += 12;
        findings.push({ type: 'suspicious_free_email', detail: `Suspicious keyword "${localHits[0]}" in sender name combined with free email provider (${domain})`, severity: 'medium' });
      }
    }

    score = clamp(score, 0, 100);
    const risk = scoreToRisk(score);
    const recommendations = generateEmailRecommendations(findings, score, domain);

    return {
      score,
      risk,
      findings,
      recommendations,
      stats: {
        localPart,
        domain,
        baseDomain,
        tld,
        isKnownProvider: legitimateDomains.has(domain)
      }
    };
  }

  function generateEmailRecommendations(findings, score, domain) {
    const recs = [];
    const types = findings.map(f => f.type);

    if (types.includes('fake_govt_email'))
      recs.push('🏛️ Indian government agencies NEVER email from Gmail/Yahoo/custom domains. Official emails are @xyz.gov.in or @xyz.nic.in only.');
    if (types.includes('indian_brand_impersonation') || types.includes('brand_impersonation') || types.includes('character_substitution'))
      recs.push('⚠️ This email is NOT from the official company. Check the exact domain carefully — scammers use slight variations. Do not click any links or reply.');
    if (types.includes('free_email_official_impersonation'))
      recs.push('🏦 Your bank, UIDAI, IRCTC, or any official service will NEVER email you from Gmail, Yahoo, or Rediffmail accounts.');
    if (types.includes('disposable'))
      recs.push('🗑️ This is a throwaway email address. Legitimate businesses never send official communication from disposable emails.');
    if (types.includes('suspicious_tld'))
      recs.push('🚫 This email is from a suspicious free domain. Mark as spam and do not interact with it.');
    if (score >= 75)
      recs.push('🛡️ HIGH RISK: Do not reply, click links, or open attachments. Report to cybercrime.gov.in or call 1930.');
    else if (score < 20)
      recs.push(`✅ Email domain "${domain}" appears relatively legitimate. Still verify the sender before acting on any request.`);

    recs.push('📧 Always hover over links before clicking to see the real URL. When in doubt, visit the official website directly.');
    return recs;
  }

  // ─── MAIN ANALYZE FUNCTION ────────────────────────────────────────────────────

  function analyze(type, input) {
    switch (type) {
      case 'message': return analyzeMessage(input);
      case 'link': return analyzeLink(input);
      case 'phone': return analyzePhone(input);
      case 'email': return analyzeEmail(input);
      default: return { error: 'Unknown analysis type.' };
    }
  }

  return { analyze, analyzeMessage, analyzeLink, analyzePhone, analyzeEmail };
})();

// Export for modules if needed
if (typeof module !== 'undefined') module.exports = ScamDetector;
