/**
 * storage.js — ScamBandhKaro local data layer
 * Provides: alerts, resources, reports, stats, learn categories
 */

const Storage = (() => {

  // ─── SEED ALERTS ───────────────────────────────────────────────────────────

  const SEED_ALERTS = [
    {
      id: 1,
      title: "Fake KYC Update SMS Targeting Bank Customers",
      description: "Fraudsters send SMS messages impersonating SBI, HDFC, and ICICI banks asking customers to 'update KYC immediately' via a phishing link. Clicking the link leads to a fake banking portal that steals credentials and OTPs.",
      severity: "high", category: "Phishing", date: "Mar 18, 2026", reports: 4821, verified: true,
      tags: ["KYC", "SMS", "Bank Fraud", "OTP Theft"],
      affectedRegions: ["Delhi", "Mumbai", "Hyderabad", "Chennai"]
    },
    {
      id: 2,
      title: "WhatsApp Job Offer Scam — Work From Home Fraud",
      description: "Victims receive WhatsApp messages offering high-paying remote jobs with no experience required. After completing 'trial tasks', they are asked to pay a registration or training fee and receive nothing in return.",
      severity: "high", category: "Job Scam", date: "Mar 17, 2026", reports: 3156, verified: true,
      tags: ["WhatsApp", "Work From Home", "Job Fraud", "Advance Fee"],
      affectedRegions: ["Bengaluru", "Pune", "Kolkata", "Hyderabad"]
    },
    {
      id: 3,
      title: "UPI QR Code Overpayment Scam",
      description: "Scammers pose as buyers on OLX or Quikr, send a QR code to 'pay' the seller, but the QR actually requests a payment instead. Victims scan it and lose money thinking they are receiving funds.",
      severity: "high", category: "UPI Fraud", date: "Mar 16, 2026", reports: 2943, verified: true,
      tags: ["UPI", "QR Code", "OLX", "Quikr"],
      affectedRegions: ["All India"]
    },
    {
      id: 4,
      title: "Fake TRAI Disconnection Call Scam",
      description: "Callers claim to be TRAI officials threatening to disconnect your phone number due to illegal activity. They connect you to a fake 'CBI officer' who demands money to resolve the issue.",
      severity: "high", category: "Impersonation", date: "Mar 15, 2026", reports: 2187, verified: true,
      tags: ["TRAI", "CBI", "Phone Scam", "Impersonation"],
      affectedRegions: ["Delhi NCR", "Mumbai", "Ahmedabad"]
    },
    {
      id: 5,
      title: "Loan App Harassment & Data Theft",
      description: "Predatory instant loan apps collect contacts, photos, and location data during signup. When repayment is demanded at extreme interest rates, they threaten to send morphed images to all contacts.",
      severity: "high", category: "Loan Fraud", date: "Mar 14, 2026", reports: 1872, verified: true,
      tags: ["Loan App", "Blackmail", "Data Theft", "Harassment"],
      affectedRegions: ["Telangana", "Andhra Pradesh", "Maharashtra"]
    },
    {
      id: 6,
      title: "Fake Electricity Bill Disconnection SMS",
      description: "An SMS claims your electricity connection will be disconnected tonight. It asks you to call a number where an agent collects your UPI details or asks for payment via a screen-sharing app.",
      severity: "medium", category: "Utility Scam", date: "Mar 13, 2026", reports: 1340, verified: true,
      tags: ["Electricity", "BESCOM", "SMS Fraud", "UPI"],
      affectedRegions: ["Karnataka", "Tamil Nadu", "UP"]
    },
    {
      id: 7,
      title: "Investment Scheme Promising 40% Monthly Returns",
      description: "Telegram and WhatsApp groups promote a stock trading or crypto investment scheme guaranteeing 40% monthly returns. Initial small profits are paid to build trust. When users invest large amounts, they are blocked.",
      severity: "high", category: "Investment Fraud", date: "Mar 12, 2026", reports: 2560, verified: true,
      tags: ["Crypto", "Stock", "Investment", "Telegram", "Ponzi"],
      affectedRegions: ["Pan India"]
    },
    {
      id: 8,
      title: "Courier Parcel Held at Customs — Pay to Release",
      description: "Victims receive a call saying an international parcel in their name is held at customs containing contraband. To avoid arrest, they are asked to pay a 'clearance fee' via UPI.",
      severity: "medium", category: "Impersonation", date: "Mar 11, 2026", reports: 987, verified: false,
      tags: ["Customs", "FedEx", "Parcel Scam", "Extortion"],
      affectedRegions: ["Delhi", "Mumbai", "Bengaluru"]
    },
    {
      id: 9,
      title: "Aadhaar-Linked SIM Swap Fraud",
      description: "Fraudsters obtain duplicate SIMs by misusing Aadhaar data. They port the victim's number to a new SIM, intercept OTPs, and empty bank accounts before the victim realizes their phone has lost network.",
      severity: "high", category: "SIM Swap", date: "Mar 10, 2026", reports: 1654, verified: true,
      tags: ["Aadhaar", "SIM Swap", "OTP", "Bank Fraud"],
      affectedRegions: ["All India"]
    },
    {
      id: 10,
      title: "Fake Google Pay Reward Points SMS",
      description: "An SMS claims accumulated reward points are expiring today and directs victims to a fake GPay phishing site. Entering credentials leads to complete account takeover.",
      severity: "medium", category: "Phishing", date: "Mar 9, 2026", reports: 763, verified: true,
      tags: ["Google Pay", "Reward Points", "Phishing", "SMS"],
      affectedRegions: ["Bengaluru", "Hyderabad", "Pune"]
    },
    {
      id: 11,
      title: "Matrimonial Site Romance Scam",
      description: "Scammers create fake profiles on matrimonial platforms, build emotional relationships over weeks, then claim to be stuck abroad in a medical emergency. They request money and vanish.",
      severity: "medium", category: "Romance Scam", date: "Mar 8, 2026", reports: 534, verified: false,
      tags: ["Matrimony", "Romance", "NRI Scam", "Emotional Fraud"],
      affectedRegions: ["Pan India"]
    },
    {
      id: 12,
      title: "Fake PM Kisan Yojana Refund Call",
      description: "Callers claim to be government officials offering a PM Kisan scheme refund. They ask for Aadhaar number and bank details to 'process the refund', then commit bank fraud.",
      severity: "low", category: "Government Impersonation", date: "Mar 7, 2026", reports: 421, verified: false,
      tags: ["PM Kisan", "Government", "Aadhaar", "Farmer Fraud"],
      affectedRegions: ["UP", "Bihar", "Rajasthan", "MP"]
    },
    {
      id: 13,
      title: "Fake Lottery / Lucky Draw SMS",
      description: "Victims receive SMS or WhatsApp messages claiming they have won a lottery or iPhone. To claim the prize, they are asked to pay a 'processing fee' or share bank details.",
      severity: "medium", category: "Lottery Scam", date: "Mar 6, 2026", reports: 892, verified: true,
      tags: ["Lottery", "Lucky Draw", "Prize Scam", "SMS"],
      affectedRegions: ["Pan India"]
    },
    {
      id: 14,
      title: "AI Deepfake Video Call Blackmail",
      description: "Scammers initiate video calls where they use deepfake AI to display obscene content. The call is secretly recorded and victims are blackmailed with the footage unless they pay money.",
      severity: "high", category: "Cyber Blackmail", date: "Mar 5, 2026", reports: 678, verified: true,
      tags: ["Deepfake", "AI", "Blackmail", "Video Call"],
      affectedRegions: ["Delhi", "Mumbai", "Bengaluru", "Hyderabad"]
    },
    {
      id: 15,
      title: "Fake Income Tax Refund Email with Malware",
      description: "Emails impersonating the Income Tax Department claim the recipient is eligible for a refund. Clicking the link downloads malware that steals banking credentials stored in the browser.",
      severity: "high", category: "Phishing", date: "Mar 4, 2026", reports: 1120, verified: true,
      tags: ["Income Tax", "Refund", "Malware", "Email Phishing"],
      affectedRegions: ["All India"]
    }
  ];

  // ─── SEED RESOURCES ─────────────────────────────────────────────────────────

  const SEED_RESOURCES = [
    { id: 1,  title: "National Cyber Crime Reporting Portal",   description: "India's official portal to file cybercrime complaints including financial fraud, social media abuse, and online scams. Available 24/7 in multiple languages.",                                                  category: "Reporting",            type: "Tool",  url: "https://cybercrime.gov.in",                                                tags: ["Official","India","Cybercrime","Complaint"] },
    { id: 2,  title: "Sanchar Saathi — SIM & Device Safety",    description: "DoT's official platform to block stolen/lost mobiles, check SIMs issued on your Aadhaar, and report suspected fraud telecom resources.",                                                                           category: "Phone Safety",         type: "Tool",  url: "https://sancharsaathi.gov.in",                                             tags: ["DoT","SIM","IMEI","Official"] },
    { id: 3,  title: "RBI Sachet — Unauthorised Investment Alert", description: "Reserve Bank of India's portal for reporting unauthorised deposit schemes, loan apps, and illegal money collection by unregistered entities.",                                                                  category: "Consumer Protection",  type: "Tool",  url: "https://sachet.rbi.org.in",                                                tags: ["RBI","Loan Fraud","Investment","Official"] },
    { id: 4,  title: "SEBI SCORES — Investment Fraud Portal",   description: "File complaints against stockbrokers, mutual funds, or investment advisors who have defrauded you via SEBI's official complaint redressal system.",                                                                category: "Reporting",            type: "Tool",  url: "https://scores.sebi.gov.in",                                               tags: ["SEBI","Stock Market","Investment","Official"] },
    { id: 5,  title: "FTC Report Fraud (USA)",                  description: "File a fraud report with the US Federal Trade Commission. Reports are shared with law enforcement agencies nationally and internationally.",                                                                         category: "Reporting",            type: "Tool",  url: "https://reportfraud.ftc.gov",                                              tags: ["FTC","USA","Official","Identity Theft"] },
    { id: 6,  title: "Have I Been Pwned — Data Breach Checker", description: "Check if your email address or phone number has appeared in a known data breach. Essential for understanding your personal exposure risk.",                                                                         category: "Identity Protection",  type: "Tool",  url: "https://haveibeenpwned.com",                                               tags: ["Data Breach","Email","Password","Privacy"] },
    { id: 7,  title: "Google Safe Browsing — URL Checker",      description: "Check if a URL is flagged as dangerous, phishing, or malware by Google's Safe Browsing database before clicking suspicious links.",                                                                                category: "Link Safety",          type: "Tool",  url: "https://transparencyreport.google.com/safe-browsing/search",               tags: ["URL","Phishing","Malware","Link Check"] },
    { id: 8,  title: "VirusTotal — File & URL Scanner",         description: "Scan any file or URL with 70+ antivirus engines and URL scanners simultaneously. Free and widely trusted by security professionals worldwide.",                                                                    category: "Link Safety",          type: "Tool",  url: "https://www.virustotal.com",                                               tags: ["Malware","URL","File Scan","Antivirus"] },
    { id: 9,  title: "Truecaller — Spam Call Identifier",       description: "Identify unknown callers, block spam calls, and report scam numbers to protect yourself and the community from phone fraud.",                                                                                      category: "Phone Safety",         type: "Tool",  url: "https://www.truecaller.com",                                               tags: ["Phone","Spam Call","Caller ID","Block"] },
    { id: 10, title: "Consumer Forum — National Consumer Helpline", description: "India's National Consumer Helpline (1800-11-4000) for filing complaints against companies for fraud, deficiency in service, or unfair trade practices.",                                                       category: "Consumer Protection",  type: "Tool",  url: "https://consumerhelpline.gov.in",                                          tags: ["Consumer Rights","India","Official","Complaint"] },
    { id: 11, title: "How to Spot a Phishing Email",            description: "A complete beginner's guide to identifying phishing emails — including fake sender addresses, urgency tactics, suspicious links, and grammar red flags.",                                                           category: "Email Safety",         type: "Guide", url: "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams", tags: ["Phishing","Email","Beginner Guide","FTC"] },
    { id: 12, title: "Freeze Your Credit — Step by Step Guide", description: "Learn how to place a credit freeze at all three major bureaus (Equifax, Experian, TransUnion) to prevent new accounts being opened in your name.",                                                                category: "Identity Protection",  type: "Guide", url: "https://consumer.ftc.gov/articles/what-know-about-credit-freezes-fraud-alerts", tags: ["Credit Freeze","Identity Theft","Guide","FTC"] },
    { id: 13, title: "UPI Safety Tips — RBI Guidelines",        description: "Official RBI guidelines on safe UPI usage: never share your UPI PIN, be cautious with QR codes, verify payee identity, and avoid screen sharing apps.",                                                           category: "Guide",                type: "Guide", url: "https://rbi.org.in",                                                       tags: ["UPI","RBI","Payment Safety","India"] },
    { id: 14, title: "MalwareBytes Browser Guard",              description: "Free browser extension that blocks malicious websites, phishing pages, scam ads, and trackers in real time. Available for Chrome and Firefox.",                                                                    category: "Link Safety",          type: "Tool",  url: "https://www.malwarebytes.com/browserguard",                                tags: ["Browser","Extension","Malware","Phishing Block"] },
    { id: 15, title: "Cyber Dost — MHA Awareness Handle",       description: "Official Ministry of Home Affairs awareness channel for cybercrime. Regularly posts alerts about new scam patterns targeting Indian citizens.",                                                                    category: "Reporting",            type: "Guide", url: "https://twitter.com/cyberdost",                                            tags: ["MHA","India","Official","Awareness"] }
  ];

  // ─── SEED LEARN CATEGORIES ──────────────────────────────────────────────────
  // icon = FA HTML string rendered directly into .learn-card-icon and detail panel

  const SEED_LEARN_CATEGORIES = [
    {
      id: "phishing",
      title: "Phishing & Email Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-envelope-open-text" style="font-size:1.6rem;color:#ef4444;"></i></div>',
      summary: "Learn how phishing attacks work and how to identify fake emails, SMS messages, and websites designed to steal your credentials.",
      fullContent: [
        { heading: "What Is Phishing?", text: "Phishing is a cyberattack where fraudsters impersonate trusted organisations — banks, government agencies, or popular apps — to trick you into revealing passwords, OTPs, or financial details. The name comes from 'fishing': attackers cast a wide net hoping someone bites. Globally, phishing is responsible for over 36% of all data breaches." },
        { heading: "How to Spot a Fake Email", text: "Check the sender's actual email address — a real SBI email comes from @sbi.co.in, not @sbi-update.com. Watch for: mismatched domains, urgency language like 'Your account will be suspended in 24 hours', generic greetings like 'Dear Customer', and hover over links before clicking to see the real URL destination." },
        { heading: "SMS Phishing (Smishing)", text: "Smishing uses SMS to deliver phishing links. Common Indian examples: fake KYC update from 'SBIINB', IRCTC booking scams, fake Aadhaar update requests, and delivery notification frauds. Golden rule: never click links in unsolicited SMS. Type the official website URL in your browser instead." },
        { heading: "Voice Phishing (Vishing)", text: "Vishing is phone-based phishing. Callers impersonate bank officials, TRAI, or the CBI and use fear tactics to extract OTPs or PIN numbers. Real banks and government agencies never ask for your OTP or PIN over the phone. If you receive such a call, hang up and call the official number on your bank's website." },
        { heading: "Real-World Example: The SBI KYC SMS Scam", text: "Victims receive 'Your SBI account will be blocked — click to update KYC' via SMS. The link opens a pixel-perfect copy of SBI's website. When the victim enters credentials, the attacker captures them in real time and transfers funds. SBI reported 4,800+ such complaints in 2025 alone. Always access your bank through the official app or by typing the URL yourself." },
        { heading: "What To Do If You Clicked", text: "If you clicked a phishing link: (1) Do not enter any information. (2) Change your passwords immediately, starting with email. (3) Enable two-factor authentication. (4) Contact your bank if financial details were shared. (5) Report to cybercrime.gov.in and forward the suspicious SMS to 1930." }
      ]
    },
    {
      id: "upi-fraud",
      title: "UPI & Digital Payment Fraud",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-mobile-screen-button" style="font-size:1.6rem;color:#f59e0b;"></i></div>',
      summary: "Understand how scammers exploit UPI, QR codes, and digital payment platforms to steal money — and how to protect yourself.",
      fullContent: [
        { heading: "The Core UPI Confusion Scammers Exploit", text: "UPI scams exploit one critical confusion: collecting a payment and sending one look identical on screen. Scammers send 'collect requests' (demands for money) disguised as payment notifications. When you enter your PIN to 'accept' the payment, money leaves your account instead. Absolute rule: you only enter your UPI PIN to SEND money. Never to receive it." },
        { heading: "QR Code Scams on OLX & Quikr", text: "Fraudsters pose as buyers and send a QR code claiming to 'pay' you. But scanning and entering your PIN sends them money instead. A legitimate QR code to receive payment NEVER asks for your PIN. If you're asked for a PIN to receive money — stop immediately and report the buyer." },
        { heading: "Screen Sharing / Remote Access Fraud", text: "Scammers posing as bank officials ask you to install AnyDesk or TeamViewer for 'assistance'. Once installed, they watch your screen and capture your UPI PIN and OTPs as you type them. Never install remote access apps at someone else's request. Your bank will never ask you to do this." },
        { heading: "Fake UPI Refund Scam", text: "Victims who have previously been defrauded are targeted by 'recovery agents' posing as cybercrime officials. They promise to recover lost money for a 'processing fee' paid via UPI. This is always a second scam. Legitimate cybercrime recovery does not involve advance fee payments." },
        { heading: "Real Case: ₹8.5 Lakh Lost in 3 Minutes", text: "A Bengaluru software engineer lost ₹8.5 lakh after a caller claiming to be from HDFC Bank's 'fraud prevention team' asked him to 'verify' his UPI by approving two collect requests. Both were payments to the scammer. He realised the fraud only when his bank balance notification arrived. No collect request approval is ever needed to 'secure' your account." },
        { heading: "Safe UPI Practices", text: "Every time you use UPI: (1) Never share your UPI PIN or OTP with anyone. (2) Verify the payee's registered name before confirming. (3) Don't use public WiFi for transactions. (4) Enable transaction limits in your banking app. (5) Use BHIM's 'check UPI ID' feature to verify suspicious payees." }
      ]
    },
    {
      id: "job-scams",
      title: "Job & Work-From-Home Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(139,92,246,0.12);border:1px solid rgba(139,92,246,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-briefcase" style="font-size:1.6rem;color:#8b5cf6;"></i></div>',
      summary: "Recognize fake job offers, task-based investment scams, and advance fee fraud targeting job seekers across India.",
      fullContent: [
        { heading: "The Anatomy of a Job Scam", text: "Job scams follow a predictable pattern: (1) Unsolicited WhatsApp or Telegram contact offering easy money. (2) Simple initial 'tasks' — like YouTube video likes or hotel ratings — with small real payments to build trust. (3) Escalating 'investment' requirements to unlock bigger earnings. (4) Complete disappearance after taking your money. Early small payments are bait, not proof of legitimacy." },
        { heading: "Task-Based Scams: India's Fastest Growing Fraud", text: "In 2025, task scams accounted for over ₹3,200 crore in losses in India. Victims are asked to complete simple online tasks and shown a growing balance on a slick dashboard. To withdraw, they must 'top up' their account. This cycle repeats with increasingly larger amounts. The dashboard and balance are entirely fake." },
        { heading: "Red Flags in Any Job Offer", text: "Walk away immediately if you see: promises of income without skills or an interview, requests for upfront registration or training fees, vague job descriptions with no verifiable company address, communication only via WhatsApp with no official email, pressure to recruit others, or pay significantly above market rate for simple tasks." },
        { heading: "Overseas Job / Visa Scams", text: "Fraudsters advertise high-paying jobs in Dubai, Canada, or Southeast Asia. They collect passport copies, visa processing fees, and travel deposits — then disappear. In documented cases from Myanmar and Cambodia in 2024–25, victims were trafficked and forced to run scam call centres. Always verify overseas offers through eMigrate.gov.in (Ministry of External Affairs)." },
        { heading: "How to Verify a Job Offer", text: "Before accepting any offer: (1) Search the company on MCA portal (mca.gov.in). (2) Call the company's official number from their main website — not the recruiter's number. (3) Never pay any fee to get a job. (4) Verify the recruiter's email domain matches the company website. (5) Check Glassdoor and LinkedIn for employee reviews." }
      ]
    },
    {
      id: "loan-fraud",
      title: "Predatory Loan App Fraud",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-hand-holding-dollar" style="font-size:1.6rem;color:#10b981;"></i></div>',
      summary: "Understand how illegal instant loan apps trap victims in debt cycles, use harassment and blackmail, and what your legal rights are.",
      fullContent: [
        { heading: "How Predatory Loan Apps Work", text: "Illegal loan apps grant small instant loans (₹5,000–₹50,000) with almost no documentation. During signup, they silently access your entire contact list, photos, and location — permissions you unknowingly grant. Interest rates range from 100–500% annually. Repayment is often demanded within 7 days. When you can't pay, systematic harassment begins." },
        { heading: "The Harassment Playbook", text: "After a missed repayment: (1) Flood your contacts with messages calling you a fraudster or criminal. (2) Send morphed or obscene images of your photo to family and colleagues. (3) Fake legal notices impersonating courts or police. (4) Threatening calls at all hours. (5) Demands for additional 'penalty payments' to stop harassment. This is illegal — file a complaint immediately." },
        { heading: "How to Identify an Illegal Loan App", text: "Illegal apps typically: are not RBI-registered NBFCs, have no physical address or customer care number, demand excessive permissions unrelated to lending, charge processing fees before disbursing the loan, and have no transparent breakdown of interest and repayment terms. Check the RBI's NBFC list at rbi.org.in before borrowing from any app." },
        { heading: "Your Legal Rights as a Victim", text: "Under Indian law: (1) Lenders cannot contact your employer or family about your personal debt without consent. (2) Sending morphed images is a criminal offence under the IT Act 2000. (3) Illegal threats constitute criminal intimidation under IPC Section 503. (4) File a cybercrime complaint at cybercrime.gov.in and call 1930. (5) You do not have to pay illegal lenders." },
        { heading: "Safe Borrowing Alternatives", text: "Legitimate options: your bank's instant personal loan, MUDRA loans for small business (mudra.org.in), Jan Dhan linked overdraft facilities, or RBI-registered NBFC apps like MoneyTap, KreditBee, or Navi. Always verify RBI registration before borrowing from any app." }
      ]
    },
    {
      id: "social-media",
      title: "Social Media & Romance Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(236,72,153,0.12);border:1px solid rgba(236,72,153,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-heart-crack" style="font-size:1.6rem;color:#ec4899;"></i></div>',
      summary: "Recognize fake profiles, catfishing, romance scams, and account takeover attempts targeting users across all platforms.",
      fullContent: [
        { heading: "Fake Profiles & Catfishing", text: "Scammers create elaborate fake profiles using stolen photos of attractive people — often military officers, doctors, or businesspeople working abroad. They invest weeks building a genuine emotional connection before introducing any financial request. Reverse image search profile photos using Google Images or TinEye to check if they appear elsewhere online." },
        { heading: "The Romance Scam Script", text: "Typical progression: (1) Initial contact on dating app, matrimonial site, or social media. (2) Quick escalation to WhatsApp for 'privacy'. (3) Declarations of love within days. (4) Claims of being abroad — military deployment, offshore oil rig, or medical mission. (5) A sudden financial crisis requiring urgent transfer. (6) Cycle of crises and requests until you stop responding." },
        { heading: "Account Cloning and Impersonation", text: "Scammers hack or clone accounts of people you know — copying their profile photo, name, and friend list. They then message mutual connections claiming an emergency and asking for urgent UPI transfers. Always verify through a direct phone call to the actual person before sending any money." },
        { heading: "Instagram Investment Scams", text: "Scammers build follower bases by posting fake luxury lifestyles, then DM followers with 'exclusive investment opportunities' in crypto or forex. They show fabricated profit screenshots. Initial deposits seem to grow on a fake dashboard. When victims try to withdraw, fees and taxes appear indefinitely. The platform and profits are entirely fake." },
        { heading: "Protecting Yourself on Social Media", text: "Key protections: (1) Set your profile to private and limit who can message you. (2) Be cautious of anyone who can never video chat. (3) Never send money to someone you haven't met in person. (4) Report fake profiles directly on the platform. (5) Use Google reverse image search on any profile photo that seems too perfect." }
      ]
    },
    {
      id: "investment-fraud",
      title: "Investment & Crypto Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(249,115,22,0.12);border:1px solid rgba(249,115,22,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-chart-line" style="font-size:1.6rem;color:#f97316;"></i></div>',
      summary: "Learn how Ponzi schemes, fake trading platforms, and crypto scams promise extraordinary returns and steal billions from victims worldwide.",
      fullContent: [
        { heading: "How Investment Scams Are Structured", text: "Investment scams follow a core formula: (1) Promise of extraordinary returns — 10%, 40%, even 100% monthly. (2) Initial payments from other victims' deposits (Ponzi structure) to 'prove' legitimacy. (3) Encouragement to invest larger amounts and recruit friends. (4) Sudden withdrawal problems blamed on 'technical issues'. (5) Complete collapse. SEBI-registered advisors are legally prohibited from guaranteeing returns." },
        { heading: "Pig Butchering Scams (Sha Zhu Pan)", text: "A stranger befriends you (often romantically) and gradually introduces a 'trading platform' where they show you earning huge returns. The platform is entirely fake — it shows fabricated profits. You are encouraged to deposit more and more until you try to withdraw, at which point the platform disappears. India's CBI tracked over ₹500 crore in pig butchering losses in 2025." },
        { heading: "Fake Crypto Exchanges and Wallets", text: "Scam crypto platforms mimic legitimate exchanges. They allow deposits and even small withdrawals to build trust. When you invest significant amounts, your funds are locked and 'release fees' demanded. Legitimate exchanges never charge fees from your wallet balance to withdraw — fees are deducted from the transaction. Verify exchanges on CoinMarketCap or Coingecko." },
        { heading: "Telegram 'Expert' Trading Groups", text: "Scam investment groups claim to have insider market information or 'algo trading' signals. They use coordinated fake testimonials and fabricated screenshots. Members share 'success stories' to pressure deposits. Once deposited, the group admin disappears or the platform shows a sudden total loss. Check if any financial advisor is registered with SEBI at sebi.gov.in." },
        { heading: "Recovering from Investment Fraud", text: "If defrauded: (1) File immediately at cybercrime.gov.in. (2) Report to SEBI SCORES if an investment advisor was involved. (3) Contact your bank to freeze connected accounts. (4) Be wary of 'recovery agents' who promise to recover money for a fee — this is almost always a second scam. Legitimate law enforcement does not charge fees to recover funds." }
      ]
    },
    {
      id: "tech-support",
      title: "Tech Support & Computer Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(59,130,246,0.12);border:1px solid rgba(59,130,246,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-laptop-code" style="font-size:1.6rem;color:#3b82f6;"></i></div>',
      summary: "Understand fake Microsoft alerts, remote access scams, and how fraudsters pretend to be tech support to steal money and data.",
      fullContent: [
        { heading: "The Fake Alert Pop-Up Scam", text: "You're browsing when a full-screen pop-up appears: 'WARNING: Your computer is infected! Call Microsoft Support IMMEDIATELY at 1800-XXX-XXX.' The screen may appear frozen. This is a browser-based scam — there is no virus. Microsoft and Apple never display warning pop-ups with phone numbers. Close the browser (use Task Manager if needed). Calling the number connects you to scammers." },
        { heading: "What Happens If You Call", text: "The scammer will: (1) Act authoritative and technical to build credibility. (2) Ask you to install remote access software (AnyDesk, TeamViewer). (3) Show you fake 'evidence' of infections in your Event Viewer. (4) Charge hundreds of rupees for fake 'virus removal'. (5) While remotely connected, steal saved passwords, banking credentials, and files." },
        { heading: "Software Subscription Renewal Scams", text: "Emails or calls claim your McAfee, Norton, or Microsoft 365 subscription has auto-renewed for ₹15,000–₹25,000. To cancel, call a number immediately. The scammer then guides you to share your screen or banking app to 'process the refund'. Legitimate software companies send renewals with your name, exact product, and invoice — not urgent phone calls." },
        { heading: "Protecting Your Computer", text: "Essential protections: (1) Keep your OS and browser updated automatically. (2) Use Windows Defender or reputable antivirus — it never creates alarming pop-ups with phone numbers. (3) Install MalwareBytes Browser Guard (free) to block malicious sites. (4) Never allow remote access unless you initiated the support request through an official channel." }
      ]
    },
    {
      id: "government-impersonation",
      title: "Government & Authority Impersonation",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-building-columns" style="font-size:1.6rem;color:#6366f1;"></i></div>',
      summary: "Learn how scammers impersonate police, CBI, TRAI, income tax, and other authorities to extort money through fear.",
      fullContent: [
        { heading: "How Authority Impersonation Works", text: "These scams exploit fear of legal consequences. Callers pose as police, CBI, Enforcement Directorate, TRAI, or income tax officials and accuse you of serious crimes — money laundering, drug trafficking, or illegal SIM card usage. They use official-sounding language, badge numbers, and fake case file numbers to seem legitimate. The goal is panic before you can think clearly." },
        { heading: "The 'Digital Arrest' Scam", text: "India's Prime Minister addressed this scam in Mann Ki Baat. Victims receive video calls from people in police uniforms or official-looking backgrounds. They claim you are 'digitally arrested' and must remain on the call. Victims are kept on video call for hours while being pressured to transfer large sums. There is no such thing as a 'digital arrest' under Indian law. This is always a scam." },
        { heading: "Fake Income Tax Raids and Notices", text: "Callers claim to be income tax officers and say your returns are flagged for tax evasion. They demand 'immediate settlement' to avoid arrest, payable via UPI. The real Income Tax Department always communicates through official written notices sent to your registered address. Officers never demand immediate UPI payments to avoid a raid." },
        { heading: "FedEx / Customs Parcel Scams", text: "A recorded or live call claims a parcel in your name was intercepted containing drugs or contraband. You must pay a 'clearance fee' or cooperate with a 'CBI investigation'. Real customs seizures are handled through official written notices. No government agency asks for fees over an unsolicited phone call." },
        { heading: "What To Do When You Receive These Calls", text: "Immediately: (1) Hang up. (2) Do not call back on the number provided. (3) Look up the official number of the agency mentioned and call them directly. (4) Never share personal documents, Aadhaar, PAN, or bank details over the phone. (5) Report to cybercrime.gov.in. Real government officials follow formal procedures — they never make urgent payment demands over unsolicited calls." }
      ]
    },
    {
      id: "identity-theft",
      title: "Identity Theft & Data Fraud",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(20,184,166,0.12);border:1px solid rgba(20,184,166,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-id-card-clip" style="font-size:1.6rem;color:#14b8a6;"></i></div>',
      summary: "Learn how fraudsters steal and misuse your Aadhaar, PAN, and personal data — and what steps to take if your identity is compromised.",
      fullContent: [
        { heading: "How Identity Theft Happens in India", text: "Your personal data can be compromised through: phishing attacks that capture Aadhaar and PAN details, data breaches at companies holding your KYC documents, SIM swap fraud letting attackers receive your OTPs, physical theft of documents or their photographs, and fake KYC update calls that harvest your demographic data. Once stolen, your identity can be used to open loans, bank accounts, or mobile numbers in your name." },
        { heading: "Aadhaar-Related Identity Fraud", text: "Your Aadhaar number alone cannot be used to steal from you — it requires biometric verification for sensitive transactions. However, fraudsters misuse Aadhaar numbers to register SIM cards, open bank accounts, and take loans. Use the 'Lock Biometrics' feature on UIDAI's website (uidai.gov.in). Check all SIMs registered on your Aadhaar at sancharsaathi.gov.in." },
        { heading: "Signs Your Identity Has Been Stolen", text: "Warning signs: unexpected credit inquiries on your CIBIL report, loan rejection due to existing loans you didn't take, bills or OTPs for accounts you never opened, SIM card suddenly losing network, or your PAN flagged for suspicious transactions. Check your CIBIL report free once a year at cibil.com." },
        { heading: "Immediate Steps If You're a Victim", text: "If you suspect identity theft: (1) File at cybercrime.gov.in immediately. (2) Alert your bank to watch for suspicious transactions. (3) Lock your Aadhaar biometrics at uidai.gov.in. (4) Request a credit freeze from CIBIL. (5) File an FIR at your local police station for fraudulent loans or accounts. (6) Notify UIDAI at 1947 if your Aadhaar was misused." },
        { heading: "Protecting Your Identity Going Forward", text: "Best practices: (1) Never share Aadhaar, PAN, or passport copies with unverified parties. (2) Use a masked Aadhaar (available on UIDAI's portal) when you must share ID. (3) Use strong, unique passwords and a password manager. (4) Enable login alerts on all financial accounts. (5) Shred documents containing personal information before disposal." }
      ]
    },
    {
      id: "online-shopping",
      title: "Online Shopping & E-Commerce Fraud",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(244,63,94,0.12);border:1px solid rgba(244,63,94,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-cart-shopping" style="font-size:1.6rem;color:#f43f5e;"></i></div>',
      summary: "Spot fake e-commerce stores, counterfeit product listings, advance payment scams, and fraudulent sellers on major platforms.",
      fullContent: [
        { heading: "Fake Shopping Websites", text: "Fraudsters create professional-looking stores with stolen product photos, fake reviews, and prices far below market value. After payment, victims receive counterfeit products, nothing at all, or completely different items. Red flags: domain recently registered, no physical address, only UPI/bank transfer accepted (no COD or card), unrealistically low prices, and contact only via WhatsApp." },
        { heading: "Social Media Shop Scams", text: "Instagram and Facebook ads frequently lead to fake shops offering luxury goods or electronics at 70–90% discounts. These shops use stolen creative from real brands. Always search the seller's name along with 'scam' or 'reviews' before purchasing. Legitimate businesses have verifiable contact details, return policies, and don't exclusively request immediate bank transfers." },
        { heading: "Advance Payment / Token Money Scams", text: "On platforms like OLX and Facebook Marketplace, sellers ask for a 'token amount' via UPI to 'hold the item'. After receiving the advance, they block you. Never pay any advance for items you haven't personally verified and inspected. Meet sellers in person at a public place for high-value transactions." },
        { heading: "Fake Delivery Notification Scams", text: "Fraudulent SMS messages claim a parcel couldn't be delivered and ask you to click a link to reschedule. The link leads to a phishing page that steals payment details or installs malware. Real courier companies send notifications from official numbers. Track packages only through official apps or by entering your tracking number on their verified website." },
        { heading: "Safe Online Shopping Checklist", text: "Before buying: (1) Shop only on established platforms with buyer protection (Amazon, Flipkart, Myntra). (2) Check that the website has HTTPS. (3) Read recent reviews specifically — scam stores often have old fake positive reviews. (4) Prefer COD or credit card payments (both offer dispute options). (5) Save all order confirmations and communication." }
      ]
    },
    {
      id: "deepfake-ai-scams",
      title: "AI & Deepfake Scams",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(168,85,247,0.12);border:1px solid rgba(168,85,247,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-microchip" style="font-size:1.6rem;color:#a855f7;"></i></div>',
      summary: "Understand the emerging threat of AI-generated voices, deepfake videos, and how criminals use artificial intelligence to make scams more convincing.",
      fullContent: [
        { heading: "What Are Deepfakes and Why They're Dangerous", text: "Deepfakes are AI-generated videos or audio that convincingly show real people saying or doing things they never did. Modern deepfake tools can clone a person's voice from as little as 3 seconds of audio. Scammers use these to impersonate family members, company executives, or government officials. In 2025, deepfake scams caused over $25 billion in global losses — a 500% increase from 2023." },
        { heading: "The 'Family Emergency' Voice Clone Scam", text: "You receive a distressed call in your child's or spouse's voice saying they've been in an accident or are in police custody. The voice is an AI clone generated from their social media videos. Before sending money: hang up and call that family member directly on their known number. Establish a secret family code word to verify real emergencies." },
        { heading: "CEO Fraud + Deepfake Video Calls", text: "Employees receive an urgent video call from what appears to be their CEO instructing an immediate large wire transfer. The video is a deepfake. This scam defrauded a Hong Kong firm of HK$200 million in 2024. Businesses should implement dual-authorization for all significant transfers and verify unusual financial instructions through a separate, pre-established channel." },
        { heading: "Deepfake Video Call Blackmail", text: "Scammers initiate video calls and use AI to overlay explicit content. The call is recorded and victims are threatened: pay or the video is shared with your contacts. In India, this is addressed under IPC Section 67A and the IT Act. File complaints at cybercrime.gov.in immediately. Do not pay — payment encourages further demands." },
        { heading: "How to Detect AI-Generated Content", text: "Spotting deepfakes: (1) Look for unnatural blinking or eye movement. (2) Facial edges may blur or distort during movement. (3) Lighting on the face may not match the background. (4) Audio may sound slightly robotic or have unnatural pauses. (5) Establish a secret code word with family members for emergencies." }
      ]
    },
    {
      id: "cyber-blackmail",
      title: "Cyber Blackmail & Sextortion",
      icon: '<div style="width:56px;height:56px;border-radius:14px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);display:flex;align-items:center;justify-content:center;"><i class="fa-solid fa-lock" style="font-size:1.6rem;color:#ef4444;"></i></div>',
      summary: "Learn how online blackmail and sextortion scams operate, what to do if you're targeted, and how to report them safely.",
      fullContent: [
        { heading: "What Is Sextortion?", text: "Sextortion is online blackmail where criminals threaten to share intimate images or videos unless demands are met. In India, cases jumped 340% in 2025. Victims include people of all ages and genders. The images may be real, stolen from devices, or fabricated using deepfake AI. Payment never stops the harassment — it marks you as someone who will pay." },
        { heading: "The 'Honey Trap' Pattern", text: "An attractive stranger connects on a dating app or social media and quickly escalates to video chat. They encourage intimate content sharing and secretly record it. Shortly after, threatening messages demand payment to prevent sharing the recording with family and employers. This is a highly organised criminal operation, often run from overseas, targeting thousands simultaneously." },
        { heading: "What to Do If Targeted", text: "Critical steps: (1) Do NOT pay — payment does not stop the blackmail. (2) Do NOT delete evidence — save all messages, profile links, and phone numbers. (3) Block the blackmailer on all platforms. (4) Report to cybercrime.gov.in (select 'Online Blackmailing') and call 1930. (5) Report the profile on the social media platform. (6) Inform someone you trust — isolation makes these situations worse." },
        { heading: "Email Sextortion Spam", text: "Millions receive mass emails claiming the sender recorded them via webcam. Emails often include a real but old password from a data breach to seem credible. This is a bluff — no recording exists. If the password in the email is current, change it immediately and check haveibeenpwned.com. Otherwise, ignore and delete." },
        { heading: "Prevention and Digital Safety", text: "Protect yourself: (1) Cover your webcam when not in use. (2) Never share intimate content online — once shared, you lose all control. (3) Review privacy settings on all social media accounts. (4) Be cautious of rapid emotional escalation from online strangers. (5) Discuss these risks openly with teenagers in your home — adolescents are disproportionately targeted." }
      ]
    }
  ];

  // ─── STATS ──────────────────────────────────────────────────────────────────

  const SEED_STATS = {
    totalReports: 127843,
    scamsBlocked: 43210,
    activeAlerts: 15,
    communitySaved: "₹2.4 Cr"
  };

  // ─── STORAGE KEYS ──────────────────────────────────────────────────────────

  const KEYS = {
    alerts:      'sbk_alerts',
    resources:   'sbk_resources',
    reports:     'sbk_reports',
    learn:       'sbk_learn',
    stats:       'sbk_stats',
    initialized: 'sbk_initialized_v5'
  };

  // ─── INIT ───────────────────────────────────────────────────────────────────

  function initializeData() {
    if (localStorage.getItem(KEYS.initialized)) return;
    localStorage.setItem(KEYS.alerts,    JSON.stringify(SEED_ALERTS));
    localStorage.setItem(KEYS.resources, JSON.stringify(SEED_RESOURCES));
    localStorage.setItem(KEYS.learn,     JSON.stringify(SEED_LEARN_CATEGORIES));
    localStorage.setItem(KEYS.reports,   JSON.stringify([]));
    localStorage.setItem(KEYS.stats,     JSON.stringify(SEED_STATS));
    localStorage.setItem(KEYS.initialized, '1');
  }

  // ─── ALERTS ─────────────────────────────────────────────────────────────────

  function getAlerts(filters = {}) {
    let alerts = JSON.parse(localStorage.getItem(KEYS.alerts) || '[]');
    const { severity, category, search } = filters;
    if (severity) alerts = alerts.filter(a => a.severity === severity);
    if (category) alerts = alerts.filter(a => a.category === category);
    if (search) {
      const q = search.toLowerCase();
      alerts = alerts.filter(a =>
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        (a.tags || []).some(t => t.toLowerCase().includes(q)) ||
        a.category.toLowerCase().includes(q)
      );
    }
    return alerts.sort((a, b) => b.id - a.id);
  }

  function addAlert(alert) {
    const alerts = JSON.parse(localStorage.getItem(KEYS.alerts) || '[]');
    alert.id = Date.now();
    alerts.unshift(alert);
    localStorage.setItem(KEYS.alerts, JSON.stringify(alerts));
    return alert;
  }

  // ─── RESOURCES ─────────────────────────────────────────────────────────────

  function getResources(filters = {}) {
    let resources = JSON.parse(localStorage.getItem(KEYS.resources) || '[]');
    const { category, type, search } = filters;
    if (category) resources = resources.filter(r => r.category === category);
    if (type)     resources = resources.filter(r => r.type === type);
    if (search) {
      const q = search.toLowerCase();
      resources = resources.filter(r =>
        r.title.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        (r.tags || []).some(t => t.toLowerCase().includes(q)) ||
        r.category.toLowerCase().includes(q)
      );
    }
    return resources;
  }

  // ─── REPORTS ───────────────────────────────────────────────────────────────

  function getReports() {
    return JSON.parse(localStorage.getItem(KEYS.reports) || '[]');
  }

  function addReport(report) {
    const reports = JSON.parse(localStorage.getItem(KEYS.reports) || '[]');
    report.id = Date.now();
    report.submittedAt = new Date().toISOString();
    report.status = 'Under Review';
    reports.unshift(report);
    localStorage.setItem(KEYS.reports, JSON.stringify(reports));
    const stats = getStats();
    stats.totalReports = (stats.totalReports || 0) + 1;
    localStorage.setItem(KEYS.stats, JSON.stringify(stats));
    return report;
  }

  function addAlertFromReport(report) {
    return addAlert({
      title:           report.title       || 'Community Reported Scam',
      description:     report.description || 'A new scam has been reported by a community member.',
      severity:        report.severity    || 'medium',
      category:        report.category   || 'Other',
      date:            new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }),
      reports:         1,
      verified:        false,
      userSubmitted:   true,
      tags:            report.tags        || [],
      affectedRegions: report.regions ? [report.regions] : ['Unknown']
    });
  }

  function getSeedAlerts(filters = {}) {
    return getAlerts(filters).filter(a => !a.userSubmitted);
  }

  function getUserAlerts(filters = {}) {
    return getAlerts(filters).filter(a => a.userSubmitted);
  }

  // ─── LEARN ─────────────────────────────────────────────────────────────────

  function getLearnCategories() {
    return JSON.parse(localStorage.getItem(KEYS.learn) || '[]');
  }

  function getLearnCategory(id) {
    return getLearnCategories().find(c => c.id === id) || null;
  }

  // ─── STATS ─────────────────────────────────────────────────────────────────

  function getStats() {
    return JSON.parse(localStorage.getItem(KEYS.stats) || JSON.stringify(SEED_STATS));
  }

  // ─── PUBLIC API ─────────────────────────────────────────────────────────────

  return {
    initializeData,
    getAlerts, getSeedAlerts, getUserAlerts, addAlert,
    getResources,
    getReports, addReport, addAlertFromReport,
    getLearnCategories, getLearnCategory,
    getStats
  };

})();