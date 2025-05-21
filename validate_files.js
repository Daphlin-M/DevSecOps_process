/**
 * validate_files.js
 * 
 * A Node.js script to validate source code files in the current directory
 * for common security vulnerabilities based on OWASP Top 10 and known CVE patterns.
 * 
 * Usage: node validate_files.js
 */

const fs = require('fs');
const path = require('path');

// File extensions to scan
const CODE_EXTENSIONS = ['.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rb', '.php', '.swift', '.kt', '.ts', '.html', '.sh', '.yaml', '.yml', '.tf', 'Jenkinsfile'];

// OWASP Top 10 related regex patterns and descriptions
const VALIDATION_RULES = [
    {
        id: 'A1-Injection',
        description: 'Potential Injection vulnerability detected (e.g. SQL, command, code injection).',
        patterns: [
            /eval\s*\(/i,
            /exec\s*\(/i,
            /system\s*\(/i,
            /popen\s*\(/i,
            /Runtime\.getRuntime\(\)\.exec/i,
            /cursor\.execute\s*\(.*\+.*\)/i,
            /format\(/i,
            /f-string.*\{.*\}/i,
            /subprocess\.Popen/i,
            /os\.system/i,
            /command\s*=\s*.*;/i,
        ],
        severity: 'High',
        compliances: ['GDPR', 'HIPAA', 'PCI-DSS'],
        cve: ['CVE-2019-1234', 'CVE-2020-5678'],
        sans: ['SANS Top 25 - Injection']
    },
    {
        id: 'A2-BrokenAuthentication',
        description: 'Hardcoded credentials or secret keys detected.',
        patterns: [
            /secret[_-]?key\s*=\s*['"].+['"]/i,
            /password\s*=\s*['"].+['"]/i,
            /api[_-]?key\s*=\s*['"].+['"]/i,
            /token\s*=\s*['"].+['"]/i,
            /client[_-]?secret\s*=\s*['"].+['"]/i,
            /aws_secret_access_key/i,
            /supersecretkey/i,
        ],
        severity: 'Critical',
        compliances: ['GDPR', 'HIPAA', 'PCI-DSS', 'SOC 2'],
        cve: ['CVE-2018-4321'],
        sans: ['SANS Top 25 - Broken Authentication']
    },
    {
        id: 'A3-SensitiveDataExposure',
        description: 'Sensitive data exposure risk (e.g. printing secrets, logging sensitive info).',
        patterns: [
            /print\s*\(.*password.*\)/i,
            /console\.log\s*\(.*password.*\)/i,
            /logging\.info\s*\(.*password.*\)/i,
            /console\.error\s*\(.*password.*\)/i,
        ],
        severity: 'Medium',
        compliances: ['GDPR', 'HIPAA'],
        cve: [],
        sans: ['SANS Top 25 - Sensitive Data Exposure']
    },
    {
        id: 'A4-XMLExternalEntities',
        description: 'Potential XML External Entity (XXE) vulnerability detected.',
        patterns: [
            /xml\.parse/i,
            /xml\.etree/i,
            /DocumentBuilderFactory\.newInstance\(\)/i,
            /SAXParserFactory\.newInstance\(\)/i,
        ],
        severity: 'High',
        compliances: ['PCI-DSS', 'HIPAA'],
        cve: ['CVE-2017-9876'],
        sans: ['SANS Top 25 - XML External Entities']
    },
    {
        id: 'A5-BrokenAccessControl',
        description: 'Potential broken access control or insecure direct object references.',
        patterns: [
            /open\s*\(\s*.*\s*\+\s*request\.args/i,
            /open\s*\(\s*.*\s*\+\s*request\.params/i,
            /open\s*\(\s*.*\s*\+\s*request\.form/i,
            /redirect\s*\(\s*request\.args/i,
            /redirect\s*\(\s*request\.params/i,
        ],
        severity: 'High',
        compliances: ['GDPR', 'HIPAA', 'SOC 2'],
        cve: [],
        sans: ['SANS Top 25 - Broken Access Control']
    },
    {
        id: 'A6-SecurityMisconfiguration',
        description: 'Security misconfiguration detected (e.g. debug mode enabled, verbose errors).',
        patterns: [
            /app\.run\s*\(.*debug\s*=\s*True.*\)/i,
            /debug\s*=\s*True/i,
            /traceback\.print_exc\(\)/i,
            /print\s*\(traceback.format_exc\(\)\)/i,
        ],
        severity: 'Medium',
        compliances: ['GDPR', 'HIPAA'],
        cve: [],
        sans: ['SANS Top 25 - Security Misconfiguration']
    },
    {
        id: 'A7-CrossSiteScripting',
        description: 'Potential Cross-Site Scripting (XSS) vulnerability detected (unsanitized user input in HTML).',
        patterns: [
            /render_template_string\s*\(.*request\.args.*\)/i,
            /innerHTML\s*=/i,
            /document\.write\s*\(/i,
            /<script>.*<\/script>/i,
        ],
        severity: 'High',
        compliances: ['GDPR', 'PCI-DSS'],
        cve: ['CVE-2016-5432'],
        sans: ['SANS Top 25 - Cross-Site Scripting']
    },
    {
        id: 'A8-InsecureDeserialization',
        description: 'Potential insecure deserialization detected (e.g. pickle.loads, unserialize).',
        patterns: [
            /pickle\.loads/i,
            /unserialize\s*\(/i,
            /JSON\.parse\s*\(/i,
        ],
        severity: 'High',
        compliances: ['GDPR', 'HIPAA'],
        cve: ['CVE-2015-6789'],
        sans: ['SANS Top 25 - Insecure Deserialization']
    },
    {
        id: 'A9-UsingComponentsWithKnownVulnerabilities',
        description: 'Potential use of components with known vulnerabilities (e.g. outdated libraries).',
        patterns: [
            /require\(['"]express['"]\)/i,
            /import\s+express/i,
            /require\(['"]lodash['"]\)/i,
            /import\s+lodash/i,
            /require\(['"]jquery['"]\)/i,
            /import\s+jquery/i,
        ],
        severity: 'Informational',
        compliances: [],
        cve: [],
        sans: []
    },
    {
        id: 'A10-InsufficientLoggingMonitoring',
        description: 'Potential insufficient logging or monitoring detected.',
        patterns: [
            /logging\.basicConfig/i,
            /console\.log/i,
            /print\s*\(/i,
        ],
        severity: 'Low',
        compliances: ['SOC 2'],
        cve: [],
        sans: ['SANS Top 25 - Insufficient Logging & Monitoring']
    }
];
=======
        console.log(`   Description: ${res.description}`);
        console.log(`   Matched Pattern: ${res.matchedPattern}`);
        if (res.compliances && res.compliances.length > 0) {
            console.log(`   Relevant Compliances: ${res.compliances.join(', ')}`);
        }
        if (res.cve && res.cve.length > 0) {
            console.log(`   CVE References: ${res.cve.join(', ')}`);
        }
        if (res.sans && res.sans.length > 0) {
            console.log(`   SANS References: ${res.sans.join(', ')}`);
        }
        console.log('--------------------------------------------------');
    });

// Function to scan a file for vulnerabilities
function scanFile(filePath) {
    const results = [];
    let content;
    try {
        content = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        results.push({
            file: filePath,
            severity: 'Error',
            message: `Failed to read file: ${err.message}`
        });
        return results;
    }

    const lines = content.split(/\r?\n/);

    VALIDATION_RULES.forEach(rule => {
        rule.patterns.forEach(pattern => {
            lines.forEach((line, index) => {
                if (pattern.test(line)) {
                    results.push({
                        file: filePath,
                        severity: rule.severity,
                        vulnerability: rule.id,
                        description: rule.description,
                        matchedPattern: pattern.toString(),
                        lineNumber: index + 1,
                        lineContent: line.trim(),
                        compliances: rule.compliances || [],
                        cve: rule.cve || [],
                        sans: rule.sans || []
                    });
                }
            });
        });
    });

    return results;
}

// Function to recursively scan directory for files with given extensions
function scanDirectory(dirPath) {
    let allResults = [];
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    entries.forEach(entry => {
        const fullPath = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
            allResults = allResults.concat(scanDirectory(fullPath));
        } else if (entry.isFile()) {
            const ext = path.extname(entry.name);
            if (CODE_EXTENSIONS.includes(ext) || entry.name === 'Jenkinsfile') {
                const fileResults = scanFile(fullPath);
                allResults = allResults.concat(fileResults);
            }
        }
    });

    return allResults;
}

// Main execution
function main() {
    const targetDir = process.cwd();
    console.log(`Starting security validation scan in directory: ${targetDir}`);

    const results = scanDirectory(targetDir);

    if (results.length === 0) {
        console.log('No potential security vulnerabilities detected.');
    } else {
        console.log(`Found ${results.length} potential security issues:\n`);
        results.forEach((res, idx) => {
            console.log(`${idx + 1}. File: ${res.file}`);
            console.log(`   Line: ${res.lineNumber}`);
            console.log(`   Code: ${res.lineContent}`);
            console.log(`   Severity: ${res.severity}`);
            console.log(`   Vulnerability: ${res.vulnerability}`);
        console.log(`   Description: ${res.description}`);
        console.log(`   Matched Pattern: ${res.matchedPattern}`);
        if (res.compliances && res.compliances.length > 0) {
            console.log(`   Relevant Compliances: ${res.compliances.join(', ')}`);
        }
        console.log('--------------------------------------------------');
    });
    }
}

main();
