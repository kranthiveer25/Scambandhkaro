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
      terms: ['urgent', 'immediately', 'act now', 'limited time', 'expires today',
        'last chance', 'final notice', 'warning', 'alert', 'critical',
        'time sensitive', 'respond now', 'don\'t delay', 'within 24 hours',
        'account suspended', 'verify now', 'immediate action required']
    },
    financial: {
      weight: 10,
      terms: ['wire transfer', 'gift card', 'bitcoin', 'crypto', 'bank account',
        'send money', 'payment required', 'fee', 'processing fee', 'lottery',
        'won', 'prize', 'inheritance', 'million dollars', 'free money',
        'cash reward', 'unclaimed funds', 'refund', 'overpayment', 'itunes card',
        'google play card', 'western union', 'moneygram', 'paypal', 'zelle']
    },
    threats: {
      weight: 12,
      terms: ['arrest', 'lawsuit', 'legal action', 'police', 'irs', 'tax', 'penalty',
        'warrant', 'court', 'debt collector', 'overdue', 'suspended', 'terminated',
        'hacked', 'compromised', 'virus detected', 'malware', 'blocked',
        'your computer', 'technical support', 'microsoft support']
    },
    personalInfo: {
      weight: 9,
      terms: ['social security', 'ssn', 'credit card', 'bank details', 'routing number',
        'account number', 'password', 'pin number', 'date of birth', 'mother\'s maiden',
        'verify your identity', 'confirm your details', 'update your information',
        'click here to verify', 'enter your credentials']
    },
    prizes: {
      weight: 7,
      terms: ['congratulations', 'you have been selected', 'lucky winner', 'you won',
        'claim your prize', 'free iphone', 'free gift', 'sweepstakes',
        'you are our winner', 'claim now', 'redeem', 'reward', 'bonus']
    },
    impersonation: {
      weight: 11,
      terms: ['amazon', 'paypal', 'netflix', 'apple', 'google', 'microsoft', 'irs',
        'social security administration', 'fbi', 'dea', 'bank of america',
        'chase bank', 'wells fargo', 'citibank', 'fedex', 'ups', 'usps',
        'delivery failed', 'package held', 'account on hold']
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
          severity: data.weight >= 10 ? 'high' : 'medium'
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
      score += 8;
      findings.push({ type: 'suspicious_links', terms: [`${urlMatches.length} URL(s) detected`], severity: 'medium' });
    }

    // Grammar/spelling issues (simple heuristic)
    const grammarErrors = (text.match(/\b(u|ur|plz|pls|asap|msg)\b/gi) || []).length;
    if (grammarErrors >= 2) {
      score += 5;
      findings.push({ type: 'grammar', terms: ['Informal/suspicious grammar patterns'], severity: 'low' });
    }

    // Excessive punctuation
    const exclCount = (text.match(/!/g) || []).length;
    if (exclCount >= 3) {
      score += 5;
      findings.push({ type: 'punctuation', terms: ['Excessive exclamation marks'], severity: 'low' });
    }

    // Phone number patterns
    const phonePattern = /\b(\+?1?\s?)?(\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b/g;
    const phones = text.match(phonePattern) || [];
    if (phones.length > 0) {
      score += 6;
      findings.push({ type: 'contact_extraction', terms: ['Phone number present — verify before calling'], severity: 'medium' });
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

    if (types.includes('financial')) recs.push('🚫 Never send money, gift cards, or cryptocurrency to someone you met online or via unsolicited contact.');
    if (types.includes('threats')) recs.push('⚠️ Legitimate government agencies (IRS, Social Security) never demand immediate payment via phone or text.');
    if (types.includes('personalInfo')) recs.push('🔒 Do not share your SSN, bank details, passwords, or PINs with anyone who contacts you unsolicited.');
    if (types.includes('impersonation')) recs.push('🔍 Contact the company directly using their official website/number — not the contact info in this message.');
    if (types.includes('prizes')) recs.push('🎰 You cannot win a contest you never entered. Legitimate prizes never require upfront fees.');
    if (types.includes('suspicious_links')) recs.push('🔗 Do not click links in this message. Navigate directly to the official website instead.');
    if (score >= 75) recs.push('🛡️ This message shows multiple high-risk indicators. Report it and block the sender immediately.');

    if (recs.length === 0) recs.push('✅ No major red flags detected, but always verify the sender\'s identity before responding.');
    return recs;
  }

  // ─── LINK DETECTOR ────────────────────────────────────────────────────────────

  const suspiciousTLDs = new Set(['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.loan', '.click', '.work', '.racing', '.download', '.stream',
    '.bid', '.win', '.party', '.science', '.trade']);

  const urlShorteners = new Set(['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'tiny.cc',
    'cutt.ly', 'rb.gy', 'shorte.st']);

  const brandNames = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'ebay', 'walmart',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'irs', 'usps',
    'fedex', 'ups', 'dhl', 'coinbase', 'binance'];

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

    // TLD check
    if (suspiciousTLDs.has(tld)) {
      score += 25;
      findings.push({ type: 'suspicious_tld', detail: `Suspicious top-level domain: ${tld}`, severity: 'high' });
    }

    // HTTP (not HTTPS)
    if (parsed.protocol === 'http:') {
      score += 15;
      findings.push({ type: 'no_https', detail: 'Not using HTTPS encryption', severity: 'medium' });
    }

    // URL Shortener
    if (urlShorteners.has(hostname)) {
      score += 20;
      findings.push({ type: 'url_shortener', detail: 'URL shortener hides the real destination', severity: 'high' });
    }

    // IP address as domain
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      score += 30;
      findings.push({ type: 'ip_address', detail: 'Domain is a raw IP address — highly suspicious', severity: 'high' });
    }

    // Brand typosquatting
    for (const brand of brandNames) {
      if (hostname.includes(brand)) {
        // Check if it's NOT the legitimate domain
        const isLegit = hostname === `${brand}.com` || hostname === `www.${brand}.com` ||
          hostname.endsWith(`.${brand}.com`);
        if (!isLegit) {
          score += 35;
          findings.push({ type: 'brand_impersonation', detail: `Possible "${brand}" impersonation: ${hostname}`, severity: 'high' });
          break;
        }
      }
      // Check for number substitutions (paypa1, g00gle)
      const obfuscated = brand.replace(/a/g, '@').replace(/o/g, '0').replace(/l/g, '1').replace(/e/g, '3');
      if (hostname.includes(obfuscated) && obfuscated !== brand) {
        score += 40;
        findings.push({ type: 'character_substitution', detail: `Character substitution detected — faking "${brand}"`, severity: 'high' });
      }
    }

    // Excessive subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount >= 3) {
      score += 15;
      findings.push({ type: 'excessive_subdomains', detail: `${subdomainCount} subdomain levels — suspicious structure`, severity: 'medium' });
    }

    // Very long URL
    if (url.length > 100) {
      score += 8;
      findings.push({ type: 'long_url', detail: 'Unusually long URL may be hiding destination', severity: 'low' });
    }

    // URL encoded characters
    const encodedCount = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedCount >= 5) {
      score += 15;
      findings.push({ type: 'url_encoding', detail: 'Heavily encoded URL — destination obfuscated', severity: 'medium' });
    }

    // Suspicious keywords in path
    const suspiciousPaths = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm', 'banking', 'credential', 'password'];
    const pathLower = path.toLowerCase();
    const pathHits = suspiciousPaths.filter(p => pathLower.includes(p));
    if (pathHits.length >= 2) {
      score += 12;
      findings.push({ type: 'suspicious_path', detail: `Suspicious path keywords: ${pathHits.join(', ')}`, severity: 'medium' });
    }

    // Numeric characters in domain name
    const numericInDomain = (hostname.match(/\d/g) || []).length;
    if (numericInDomain >= 4) {
      score += 10;
      findings.push({ type: 'numeric_domain', detail: 'Unusual number of digits in domain name', severity: 'low' });
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

    if (types.includes('url_shortener')) recs.push('🔍 Expand shortened URLs using a tool like checkshorturl.com before clicking.');
    if (types.includes('brand_impersonation') || types.includes('character_substitution')) {
      recs.push('⚠️ This link is mimicking a trusted brand. Visit the official site by typing the URL directly in your browser.');
    }
    if (types.includes('ip_address')) recs.push('🚫 Legitimate websites use domain names, not IP addresses. Do not visit this link.');
    if (types.includes('no_https')) recs.push('🔒 This site does not use HTTPS. Never enter personal information on non-HTTPS pages.');
    if (types.includes('suspicious_tld')) recs.push('⚠️ Free TLDs are frequently used for scam websites. Treat with extreme caution.');
    if (score >= 75) recs.push('🛡️ High-risk link detected. We strongly advise you NOT to visit this URL.');
    if (score < 20) recs.push('✅ This link appears safe, but always verify the site\'s identity before entering sensitive information.');

    return recs;
  }

  // ─── PHONE DETECTOR ───────────────────────────────────────────────────────────

  const scamAreaCodes = new Set([
    '268', '284', '473', '649', '664', '767', '784', '809', '829', '849',
    '876', '900', '976', // Premium rate
    '246', '242', '441', // Caribbean codes used in scams
  ]);

  const scamCountryCodes = new Set(['+44', '+92', '+91', '+234', '+216', '+212', '+254', '+256']);

  function analyzePhone(phone) {
    if (!phone || phone.trim().length < 5) {
      return { error: 'Please enter a phone number to analyze.' };
    }

    const clean = phone.trim();
    const digitsOnly = clean.replace(/\D/g, '');
    let score = 0;
    const findings = [];

    // Premium rate numbers
    if (/^\+?1?900/.test(digitsOnly) || /^\+?976/.test(digitsOnly)) {
      score += 45;
      findings.push({ type: 'premium_rate', detail: 'This is a premium-rate number — calling may incur high charges', severity: 'high' });
    }

    // Area code check (US numbers)
    if (digitsOnly.length === 10 || (digitsOnly.length === 11 && digitsOnly[0] === '1')) {
      const areaCode = digitsOnly.length === 11 ? digitsOnly.substring(1, 4) : digitsOnly.substring(0, 3);
      if (scamAreaCodes.has(areaCode)) {
        score += 35;
        findings.push({ type: 'high_risk_area', detail: `Area code ${areaCode} is frequently associated with scam calls`, severity: 'high' });
      }
    }

    // International country codes
    for (const code of scamCountryCodes) {
      if (clean.startsWith(code)) {
        score += 20;
        findings.push({ type: 'scam_country_code', detail: `Country code ${code} frequently appears in reported scam calls`, severity: 'medium' });
        break;
      }
    }

    // Pattern: repeated digits
    if (/(\d)\1{5,}/.test(digitsOnly)) {
      score += 15;
      findings.push({ type: 'suspicious_pattern', detail: 'Unusual repeating digit pattern', severity: 'low' });
    }

    // Too short or too long
    if (digitsOnly.length < 7) {
      score += 10;
      findings.push({ type: 'invalid_length', detail: 'Number is too short to be a valid phone number', severity: 'medium' });
    } else if (digitsOnly.length > 15) {
      score += 10;
      findings.push({ type: 'invalid_length', detail: 'Number is unusually long', severity: 'low' });
    }

    // Known scam patterns (e.g., sequential: 1234567890)
    const sequential = '0123456789';
    if (sequential.includes(digitsOnly.slice(-7))) {
      score += 8;
      findings.push({ type: 'sequential_pattern', detail: 'Sequential number pattern detected', severity: 'low' });
    }

    // Spoofed local patterns
    if (/^(202|800|888|877|866|855|844|833|822)\d{7}$/.test(digitsOnly)) {
      score += 5;
      findings.push({ type: 'toll_free', detail: 'Toll-free numbers can be spoofed — verify the caller\'s identity', severity: 'low' });
    }

    score = clamp(score, 0, 100);
    const risk = scoreToRisk(score);

    const recommendations = [
      score >= 75 ? '🚫 Do not call or respond to this number. Block and report it.' :
        score >= 45 ? '⚠️ Be cautious. Verify this number through official channels before calling back.' :
          '✅ No major red flags, but verify the caller\'s identity before sharing any personal information.'
    ];

    if (findings.some(f => f.type === 'premium_rate')) {
      recommendations.push('💰 Calling premium-rate numbers can result in charges of $20+ per minute. Avoid calling back unknown numbers.');
    }

    recommendations.push('📋 Report suspicious calls to the FTC at reportfraud.ftc.gov or by calling 1-877-382-4357.');

    return {
      score,
      risk,
      findings,
      recommendations,
      stats: {
        rawNumber: clean,
        digitsOnly,
        length: digitsOnly.length,
        hasCountryCode: clean.startsWith('+') || digitsOnly.startsWith('1') && digitsOnly.length === 11
      }
    };
  }

  // ─── EMAIL DETECTOR ───────────────────────────────────────────────────────────

  const disposableDomains = new Set([
    'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
    'sharklasers.com', 'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
    'spam4.me', 'trashmail.com', 'yopmail.com', 'maildrop.cc', '10minutemail.com',
    'fakeinbox.com', 'mailnull.com', 'spamgourmet.com', 'dispostable.com',
    'getairmail.com', 'mailnesia.com', 'spamfree24.org', 'trashmail.at'
  ]);

  const legitimateDomains = new Set([
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com',
    'live.com', 'msn.com', 'aol.com', 'protonmail.com', 'mail.com'
  ]);

  const suspiciousEmailKeywords = ['noreply', 'no-reply', 'donotreply', 'admin', 'security',
    'verify', 'alert', 'notification', 'support', 'help', 'service', 'info',
    'billing', 'account', 'update', 'confirm', 'reset'];

  function analyzeEmail(email) {
    if (!email || !email.includes('@')) {
      return { error: 'Please enter a valid email address to analyze.' };
    }

    const clean = email.trim().toLowerCase();
    const [localPart, domain] = clean.split('@');
    if (!domain) return { error: 'Invalid email format.' };

    const domainParts = domain.split('.');
    const tld = '.' + domainParts[domainParts.length - 1];
    const baseDomain = domainParts.slice(-2).join('.');

    let score = 0;
    const findings = [];

    // Disposable email
    if (disposableDomains.has(domain)) {
      score += 40;
      findings.push({ type: 'disposable', detail: 'Disposable/temporary email service detected', severity: 'high' });
    }

    // Brand typosquatting in domain
    for (const brand of brandNames) {
      if (domain.includes(brand) && !legitimateDomains.has(domain)) {
        // Check if it's an official domain
        const officialDomains = [`${brand}.com`, `${brand}.org`, `${brand}.net`];
        if (!officialDomains.includes(baseDomain)) {
          score += 35;
          findings.push({ type: 'brand_impersonation', detail: `Domain appears to impersonate "${brand}"`, severity: 'high' });
          break;
        }
      }
    }

    // Suspicious TLD in email domain
    if (suspiciousTLDs.has(tld)) {
      score += 25;
      findings.push({ type: 'suspicious_tld', detail: `Suspicious email TLD: ${tld}`, severity: 'high' });
    }

    // Numbers in domain (not counting known providers)
    const numericMatches = (baseDomain.match(/\d/g) || []).length;
    if (numericMatches >= 3 && !legitimateDomains.has(domain)) {
      score += 15;
      findings.push({ type: 'numeric_domain', detail: 'Unusual numbers in email domain', severity: 'medium' });
    }

    // Suspicious local part keywords
    const localHits = suspiciousEmailKeywords.filter(kw => localPart.includes(kw));
    if (localHits.length >= 2) {
      score += 12;
      findings.push({ type: 'suspicious_local', detail: `Suspicious sender prefix: ${localHits.slice(0, 2).join(', ')}`, severity: 'medium' });
    }

    // Hyphen-heavy domain (common scam pattern)
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 10;
      findings.push({ type: 'hyphenated_domain', detail: 'Excessively hyphenated domain name', severity: 'low' });
    }

    // Very long local part
    if (localPart.length > 30) {
      score += 8;
      findings.push({ type: 'long_local', detail: 'Unusually long sender name in email address', severity: 'low' });
    }

    // Numbers in local part (like security82736@gmail.com)
    const localNums = (localPart.match(/\d/g) || []).length;
    if (localNums >= 5) {
      score += 8;
      findings.push({ type: 'numeric_local', detail: 'Many digits in sender name may indicate auto-generated address', severity: 'low' });
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

    if (types.includes('disposable')) recs.push('🗑️ This is a disposable email. Legitimate companies never use throwaway addresses.');
    if (types.includes('brand_impersonation')) {
      recs.push('⚠️ This email domain is NOT the official company domain. Do not click any links or reply with personal info.');
    }
    if (types.includes('suspicious_tld')) recs.push('🚫 Free TLD domains are commonly used for scam emails. Mark as spam and delete.');
    if (score >= 75) recs.push('🛡️ High risk email detected. Do not reply, click links, or open attachments.');
    if (score < 20) recs.push(`✅ This email domain (${domain}) appears legitimate. Still verify the sender before acting.`);

    recs.push('📧 When in doubt, contact the company directly through their official website, not via this email.');
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
