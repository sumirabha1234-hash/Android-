import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ApkAnalysisResult, SecurityVulnerability, ExtractedEndpoint, AndroidPermission, HardcodedSecret } from '../types';

export interface ReportCustomizationOptions {
  auditorName: string;
  organization: string;
  reportTitle: string;
  includeExecutiveSummary: boolean;
  includeVulnerabilities: boolean;
  includePermissions: boolean;
  includeEndpoints: boolean;
  includeSignatures: boolean;
  includeSecrets: boolean;
  includeSandbox: boolean;
  includeDecompiledFilesList: boolean;
  // Filters
  severityFilter: {
    critical: boolean;
    high: boolean;
    medium: boolean;
    low: boolean;
    info: boolean;
  };
  endpointInsecureOnly: boolean;
  permissionDangerousOnly: boolean;
}

export const DEFAULT_REPORT_OPTIONS: ReportCustomizationOptions = {
  auditorName: 'Security Auditor',
  organization: 'SecOps Audit Team',
  reportTitle: 'Android Binary Security & Compliance Audit',
  includeExecutiveSummary: true,
  includeVulnerabilities: true,
  includePermissions: true,
  includeEndpoints: true,
  includeSignatures: true,
  includeSecrets: true,
  includeSandbox: true,
  includeDecompiledFilesList: false,
  severityFilter: {
    critical: true,
    high: true,
    medium: true,
    low: true,
    info: true,
  },
  endpointInsecureOnly: false,
  permissionDangerousOnly: false,
};

/**
 * Filter vulnerabilities based on selected severities
 */
export function getFilteredVulnerabilities(
  vulnerabilities: SecurityVulnerability[],
  severityFilter: ReportCustomizationOptions['severityFilter']
): SecurityVulnerability[] {
  return vulnerabilities.filter((v) => {
    const sev = v.severity.toLowerCase() as keyof ReportCustomizationOptions['severityFilter'];
    return severityFilter[sev] ?? true;
  });
}

/**
 * Filter endpoints
 */
export function getFilteredEndpoints(
  endpoints: ExtractedEndpoint[],
  insecureOnly: boolean
): ExtractedEndpoint[] {
  if (!insecureOnly) return endpoints;
  return endpoints.filter((e) => e.isInsecure);
}

/**
 * Filter permissions
 */
export function getFilteredPermissions(
  permissions: AndroidPermission[],
  dangerousOnly: boolean
): AndroidPermission[] {
  if (!dangerousOnly) return permissions;
  return permissions.filter((p) => p.isDangerous || p.protectionLevel === 'dangerous');
}

/**
 * Generates an executive PDF report using jsPDF and autoTable
 */
export async function generatePdfReport(
  analysis: ApkAnalysisResult,
  options: ReportCustomizationOptions = DEFAULT_REPORT_OPTIONS
): Promise<Blob> {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let currentY = 15;

  // Primary palette
  const primaryColor: [number, number, number] = [14, 116, 144]; // Cyan-700
  const darkColor: [number, number, number] = [15, 23, 42]; // Slate-900
  const mutedColor: [number, number, number] = [100, 116, 139]; // Slate-500
  const dangerColor: [number, number, number] = [225, 29, 72]; // Rose-600

  // 1. Header Banner
  doc.setFillColor(...darkColor);
  doc.rect(0, 0, pageWidth, 38, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.text(options.reportTitle, 14, 15);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184);
  doc.text(`Package: ${analysis.packageName} | Version: ${analysis.versionName} (Build ${analysis.versionCode})`, 14, 22);
  doc.text(`Auditor: ${options.auditorName || 'Security Analyst'} | Org: ${options.organization || 'Internal Audit'} | Generated: ${new Date().toLocaleDateString()}`, 14, 28);
  doc.text(`Target SDK: ${analysis.targetSdkVersion} | Min SDK: ${analysis.minSdkVersion} | Size: ${(analysis.fileSize / (1024 * 1024)).toFixed(2)} MB`, 14, 34);

  // Security Score Badge in top right
  const scoreBadgeX = pageWidth - 42;
  doc.setFillColor(
    analysis.securityScore >= 80 ? 16 : analysis.securityScore >= 50 ? 217 : 225,
    analysis.securityScore >= 80 ? 185 : analysis.securityScore >= 50 ? 119 : 29,
    analysis.securityScore >= 80 ? 129 : analysis.securityScore >= 50 ? 6 : 72
  );
  doc.roundedRect(scoreBadgeX, 8, 30, 22, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.text('SECURITY SCORE', scoreBadgeX + 15, 14, { align: 'center' });
  doc.setFontSize(14);
  doc.text(`${analysis.securityScore}/100`, scoreBadgeX + 15, 22, { align: 'center' });
  doc.setFontSize(8);
  doc.text(`Grade: ${analysis.securityRating}`, scoreBadgeX + 15, 27, { align: 'center' });

  currentY = 46;

  // 2. Executive Summary Section
  if (options.includeExecutiveSummary) {
    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text('1. Executive Threat Summary & Statistics', 14, currentY);
    currentY += 6;

    const filteredVulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);
    const criticalCount = filteredVulns.filter((v) => v.severity === 'critical').length;
    const highCount = filteredVulns.filter((v) => v.severity === 'high').length;
    const medCount = filteredVulns.filter((v) => v.severity === 'medium').length;
    const lowCount = filteredVulns.filter((v) => v.severity === 'low' || v.severity === 'info').length;

    autoTable(doc, {
      startY: currentY,
      head: [['Metric', 'Value', 'Security Implication / Standard']],
      body: [
        ['Overall Threat Level', analysis.threatLevel.toUpperCase(), analysis.threatLevel === 'Safe' ? 'Conforms to security baseline' : 'Immediate remediation recommended before release'],
        ['Critical Vulnerabilities', `${criticalCount}`, 'Direct exploitability, credential leaks, or complete process takeover'],
        ['High Risk Flaws', `${highCount}`, 'Cleartext traffic, unprotected exported components, weak cryptography'],
        ['Medium / Low Risk Flaws', `${medCount + lowCount}`, 'Information disclosure, backup permissions, deprecated configs'],
        ['Dangerous Permissions', `${analysis.permissions.filter(p => p.isDangerous).length} requested`, 'Requires explicit runtime prompt & user consent'],
        ['Hardcoded Secrets & Keys', `${analysis.secrets.length} found`, 'Private API keys, tokens, or endpoints embedded in bytecode'],
        ['Binary SHA-256 Digest', `${analysis.sha256.substring(0, 36)}...`, 'Cryptographic hash for chain-of-custody verification'],
      ],
      theme: 'grid',
      headStyles: { fillColor: primaryColor, textColor: 255, fontStyle: 'bold', fontSize: 8 },
      bodyStyles: { fontSize: 8, textColor: darkColor },
      styles: { cellPadding: 2 },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 2. Vulnerabilities Breakdown
  if (options.includeVulnerabilities) {
    const vulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);

    if (currentY > 220) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text(`2. Security Vulnerability Findings (${vulns.length})`, 14, currentY);
    currentY += 5;

    const vulnRows = vulns.map((v) => [
      v.severity.toUpperCase(),
      `${v.title}\n[${v.cwe || 'CWE'} | ${v.masvsId || 'MASVS'}]`,
      v.location || 'Bytecode / Manifest',
      v.impact,
      v.recommendation,
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Severity', 'Vulnerability & Standards', 'Location', 'Impact', 'Remediation']],
      body: vulnRows,
      theme: 'grid',
      headStyles: { fillColor: dangerColor, textColor: 255, fontStyle: 'bold', fontSize: 8 },
      bodyStyles: { fontSize: 7.5, textColor: darkColor },
      columnStyles: {
        0: { cellWidth: 20, fontStyle: 'bold' },
        1: { cellWidth: 45 },
        2: { cellWidth: 35 },
        3: { cellWidth: 45 },
        4: { cellWidth: 40 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 0) {
          const val = String(data.cell.raw).toUpperCase();
          if (val === 'CRITICAL') {
            data.cell.styles.textColor = [225, 29, 72];
          } else if (val === 'HIGH') {
            data.cell.styles.textColor = [234, 88, 12];
          } else if (val === 'MEDIUM') {
            data.cell.styles.textColor = [202, 138, 4];
          } else {
            data.cell.styles.textColor = [14, 116, 144];
          }
        }
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 3. Hardcoded Secrets (if enabled)
  if (options.includeSecrets && analysis.secrets && analysis.secrets.length > 0) {
    if (currentY > 220) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text(`3. Discovered Hardcoded Secrets & Credentials (${analysis.secrets.length})`, 14, currentY);
    currentY += 5;

    const secretRows = analysis.secrets.map((s) => [
      s.severity.toUpperCase(),
      s.name,
      s.type,
      s.value,
      s.file,
      `${s.entropy.toFixed(2)}`,
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Severity', 'Secret Name', 'Type', 'Masked / Extracted Value', 'Source File', 'Entropy']],
      body: secretRows,
      theme: 'grid',
      headStyles: { fillColor: [180, 83, 9], textColor: 255, fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 4. Network Endpoints
  if (options.includeEndpoints) {
    const endpoints = getFilteredEndpoints(analysis.endpoints, options.endpointInsecureOnly);

    if (currentY > 220) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text(`4. Network Endpoints & Reconnaissance (${endpoints.length})`, 14, currentY);
    currentY += 5;

    const endpointRows = endpoints.map((e) => [
      e.isInsecure ? 'INSECURE' : 'SECURE',
      e.url,
      e.protocol,
      e.category,
      e.sourceFile || 'Bytecode StringPool',
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Security', 'URL / Host / IP Endpoint', 'Protocol', 'Category', 'Source File']],
      body: endpointRows,
      theme: 'grid',
      headStyles: { fillColor: primaryColor, textColor: 255, fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
      columnStyles: {
        0: { cellWidth: 22, fontStyle: 'bold' },
        1: { cellWidth: 70 },
        2: { cellWidth: 25 },
        3: { cellWidth: 35 },
        4: { cellWidth: 35 },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 0) {
          if (data.cell.raw === 'INSECURE') {
            data.cell.styles.textColor = [225, 29, 72];
          } else {
            data.cell.styles.textColor = [16, 185, 129];
          }
        }
      },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 5. Permissions Matrix
  if (options.includePermissions) {
    const permissions = getFilteredPermissions(analysis.permissions, options.permissionDangerousOnly);

    if (currentY > 220) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text(`5. Android Permissions Assessment (${permissions.length})`, 14, currentY);
    currentY += 5;

    const permRows = permissions.map((p) => [
      p.shortName || p.name,
      p.protectionLevel.toUpperCase(),
      p.category,
      p.isDangerous ? 'YES (High Privacy Impact)' : 'Standard',
      p.riskAssessment || p.description,
    ]);

    autoTable(doc, {
      startY: currentY,
      head: [['Permission', 'Level', 'Category', 'Dangerous', 'Risk Assessment']],
      body: permRows,
      theme: 'striped',
      headStyles: { fillColor: [71, 85, 105], textColor: 255, fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 6. Signatures & Certificates
  if (options.includeSignatures && analysis.signature) {
    if (currentY > 220) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text('6. Cryptographic Signature & Certificate Audit', 14, currentY);
    currentY += 5;

    const sigRows = [
      ['APK Signature Scheme', analysis.signature.schemeVersion],
      ['Validity & Integrity', analysis.signature.isValid ? 'Valid APK Signature' : 'Invalid / Corrupt'],
      ['Self-Signed Status', analysis.signature.isSelfSigned ? 'Self-Signed (Debug/Internal)' : 'CA Trusted'],
      ['Subject (Distinguished Name)', analysis.signature.subject],
      ['Issuer (Signing Authority)', analysis.signature.issuer],
      ['Public Key Algorithm & Size', `${analysis.signature.algorithm} (${analysis.signature.keySize} bits)`],
      ['Validity Period', `${analysis.signature.validFrom} to ${analysis.signature.validTo}`],
      ['SHA-256 Fingerprint', analysis.signature.sha256Fingerprint],
    ];

    autoTable(doc, {
      startY: currentY,
      head: [['Certificate Field', 'Audit Value']],
      body: sigRows,
      theme: 'grid',
      headStyles: { fillColor: primaryColor, textColor: 255, fontSize: 8 },
      bodyStyles: { fontSize: 7.5 },
      margin: { left: 14, right: 14 },
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // 7. Isolated Fake Android Sandbox Simulation & Intercepted Downloads
  if (options.includeSandbox && analysis.dynamicSandbox) {
    const sandbox = analysis.dynamicSandbox;
    if (currentY > 210) {
      doc.addPage();
      currentY = 20;
    }

    doc.setTextColor(...darkColor);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text(`7. Isolated Android Sandbox & Dynamic Download Interception`, 14, currentY);
    currentY += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(...mutedColor);
    doc.text(
      `Environment: ${sandbox.environment.osVersion} | Verdict: ${sandbox.verdict} | Trapped Downloads: ${sandbox.downloadedFiles.length}`,
      14,
      currentY
    );
    currentY += 5;

    if (sandbox.downloadedFiles.length > 0) {
      const dlRows = sandbox.downloadedFiles.map((d) => [
        d.riskLevel,
        d.fileName,
        d.riskLabel,
        d.url,
        d.destinationPath,
        d.downloadMethod,
      ]);

      autoTable(doc, {
        startY: currentY,
        head: [['Severity', 'File Name', 'Payload Type', 'Download URL', 'Destination VFS', 'Method']],
        body: dlRows,
        theme: 'striped',
        headStyles: { fillColor: [225, 29, 72], textColor: 255, fontSize: 7.5 },
        bodyStyles: { fontSize: 7 },
        columnStyles: {
          0: { cellWidth: 18, fontStyle: 'bold' },
          1: { cellWidth: 28 },
          2: { cellWidth: 34 },
          3: { cellWidth: 45 },
          4: { cellWidth: 35 },
          5: { cellWidth: 20 },
        },
        margin: { left: 14, right: 14 },
      });
    } else {
      autoTable(doc, {
        startY: currentY,
        head: [['Dynamic Execution Status', 'Sandbox Verdict']],
        body: [
          [
            'Clean Dynamic Execution',
            'No unauthorized background file downloads, secondary APK droppers, or dynamic DEX payloads detected.',
          ],
        ],
        theme: 'grid',
        headStyles: { fillColor: [16, 185, 129], textColor: 255, fontSize: 8 },
        bodyStyles: { fontSize: 7.5 },
        margin: { left: 14, right: 14 },
      });
    }
  }

  // Page Footers
  const totalPages = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(...mutedColor);
    doc.text(
      `CONFIDENTIAL SECURITY AUDIT REPORT - ${analysis.packageName} | Page ${i} of ${totalPages}`,
      pageWidth / 2,
      doc.internal.pageSize.getHeight() - 8,
      { align: 'center' }
    );
  }

  return doc.output('blob');
}

/**
 * Generates CSV string for any dataset
 */
export function generateCsvReport(
  analysis: ApkAnalysisResult,
  dataset: 'all' | 'vulnerabilities' | 'endpoints' | 'permissions' | 'secrets',
  options: ReportCustomizationOptions = DEFAULT_REPORT_OPTIONS
): string {
  const escapeCsv = (str: any) => {
    if (str === null || str === undefined) return '""';
    const s = String(str).replace(/"/g, '""');
    return `"${s}"`;
  };

  const sections: string[] = [];

  // Header metadata
  sections.push([
    '# Android Security Audit Report',
    `# Package: ${analysis.packageName}`,
    `# App Name: ${analysis.appName || 'Android App'}`,
    `# Version: ${analysis.versionName} (${analysis.versionCode})`,
    `# Security Score: ${analysis.securityScore}/100 (${analysis.securityRating})`,
    `# Threat Level: ${analysis.threatLevel}`,
    `# Date: ${new Date().toISOString()}`,
    '',
  ].join('\n'));

  // Vulnerabilities CSV
  if (dataset === 'all' || dataset === 'vulnerabilities') {
    const vulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);
    const headers = ['ID', 'Title', 'Severity', 'Category', 'CWE', 'OWASP_MASVS', 'Location', 'Impact', 'Recommendation'];
    const rows = vulns.map((v) => [
      escapeCsv(v.id),
      escapeCsv(v.title),
      escapeCsv(v.severity),
      escapeCsv(v.category),
      escapeCsv(v.cwe || 'N/A'),
      escapeCsv(v.masvsId || 'N/A'),
      escapeCsv(v.location || 'N/A'),
      escapeCsv(v.impact),
      escapeCsv(v.recommendation),
    ].join(','));

    sections.push(['### VULNERABILITY FINDINGS', headers.join(','), ...rows, ''].join('\n'));
  }

  // Hardcoded Secrets CSV
  if (dataset === 'all' || dataset === 'secrets') {
    const headers = ['Secret Name', 'Type', 'Severity', 'File Location', 'Entropy', 'Value'];
    const rows = analysis.secrets.map((s) => [
      escapeCsv(s.name),
      escapeCsv(s.type),
      escapeCsv(s.severity),
      escapeCsv(s.file),
      escapeCsv(s.entropy),
      escapeCsv(s.value),
    ].join(','));

    sections.push(['### HARDCODED SECRETS', headers.join(','), ...rows, ''].join('\n'));
  }

  // Endpoints CSV
  if (dataset === 'all' || dataset === 'endpoints') {
    const endpoints = getFilteredEndpoints(analysis.endpoints, options.endpointInsecureOnly);
    const headers = ['URL / Host', 'Protocol', 'Type', 'Category', 'Insecure', 'Source File'];
    const rows = endpoints.map((e) => [
      escapeCsv(e.url),
      escapeCsv(e.protocol),
      escapeCsv(e.type),
      escapeCsv(e.category),
      escapeCsv(e.isInsecure ? 'YES' : 'NO'),
      escapeCsv(e.sourceFile || 'Dalvik Bytecode'),
    ].join(','));

    sections.push(['### NETWORK RECONNAISSANCE ENDPOINTS', headers.join(','), ...rows, ''].join('\n'));
  }

  // Permissions CSV
  if (dataset === 'all' || dataset === 'permissions') {
    const permissions = getFilteredPermissions(analysis.permissions, options.permissionDangerousOnly);
    const headers = ['Permission Name', 'Short Name', 'Protection Level', 'Dangerous', 'Category', 'Risk Assessment'];
    const rows = permissions.map((p) => [
      escapeCsv(p.name),
      escapeCsv(p.shortName),
      escapeCsv(p.protectionLevel),
      escapeCsv(p.isDangerous ? 'YES' : 'NO'),
      escapeCsv(p.category),
      escapeCsv(p.riskAssessment || p.description),
    ].join(','));

    sections.push(['### PERMISSIONS MATRIX', headers.join(','), ...rows, ''].join('\n'));
  }

  return sections.join('\n\n');
}

/**
 * Generates formatted Markdown report
 */
export function generateMarkdownReport(
  analysis: ApkAnalysisResult,
  options: ReportCustomizationOptions = DEFAULT_REPORT_OPTIONS
): string {
  const vulns = getFilteredVulnerabilities(analysis.vulnerabilities, options.severityFilter);
  const endpoints = getFilteredEndpoints(analysis.endpoints, options.endpointInsecureOnly);
  const permissions = getFilteredPermissions(analysis.permissions, options.permissionDangerousOnly);

  let md = `# Security Audit Report: ${analysis.appName || analysis.packageName}

**Package Name:** \`${analysis.packageName}\`  
**Version:** \`${analysis.versionName}\` (Code \`${analysis.versionCode}\`)  
**Security Score:** **${analysis.securityScore}/100** (Rating: **${analysis.securityRating}**, Threat Level: **${analysis.threatLevel}**)  
**Audit Date:** ${new Date().toUTCString()}  
**Target SDK:** ${analysis.targetSdkVersion} | **Min SDK:** ${analysis.minSdkVersion}  
**SHA-256 Digest:** \`${analysis.sha256}\`  

---

## 1. Executive Summary

- **Total Critical Vulnerabilities:** ${analysis.stats.criticalIssues}
- **Total High Risk Vulnerabilities:** ${analysis.stats.highIssues}
- **Total Dangerous Permissions:** ${analysis.stats.dangerousPermissionsCount}
- **Exported Components:** ${analysis.stats.exportedComponentsCount}
- **Extracted Endpoints & URLs:** ${analysis.stats.externalUrlsCount}

---
`;

  if (options.includeVulnerabilities && vulns.length > 0) {
    md += `## 2. Vulnerability Findings (${vulns.length})

| Severity | Title | CWE / MASVS | Location |
| :--- | :--- | :--- | :--- |
${vulns.map((v) => `| **${v.severity.toUpperCase()}** | ${v.title} | ${v.cwe || 'CWE'} / ${v.masvsId || 'MASVS'} | \`${v.location || 'Bytecode'}\` |`).join('\n')}

### Detailed Findings:

${vulns.map((v) => `#### [${v.severity.toUpperCase()}] ${v.title}
- **CWE:** ${v.cwe || 'N/A'} | **OWASP MASVS:** ${v.masvsId || 'N/A'}
- **Location:** \`${v.location || 'AndroidManifest.xml / Bytecode'}\`
- **Impact:** ${v.impact}
- **Recommendation:** ${v.recommendation}
${v.codeSnippet ? `\`\`\`${v.category === 'manifest' ? 'xml' : 'java'}\n${v.codeSnippet}\n\`\`\`` : ''}
`).join('\n\n')}

---
`;
  }

  if (options.includeSecrets && analysis.secrets.length > 0) {
    md += `## 3. Hardcoded Secrets & Credentials (${analysis.secrets.length})

| Severity | Secret Name | Type | Value | File |
| :--- | :--- | :--- | :--- | :--- |
${analysis.secrets.map((s) => `| **${s.severity.toUpperCase()}** | ${s.name} | ${s.type} | \`${s.value}\` | \`${s.file}\` |`).join('\n')}

---
`;
  }

  if (options.includeEndpoints && endpoints.length > 0) {
    md += `## 4. Network Endpoints & Threat Intel (${endpoints.length})

| Status | URL / Host | Protocol | Category | Source |
| :--- | :--- | :--- | :--- | :--- |
${endpoints.map((e) => `| ${e.isInsecure ? '🔴 INSECURE' : '🟢 SECURE'} | \`${e.url}\` | ${e.protocol} | ${e.category} | \`${e.sourceFile || 'classes.dex'}\` |`).join('\n')}

---
`;
  }

  if (options.includePermissions && permissions.length > 0) {
    md += `## 5. Android Permissions (${permissions.length})

| Permission | Protection | Dangerous | Risk Assessment |
| :--- | :--- | :--- | :--- |
${permissions.map((p) => `| \`${p.shortName}\` | ${p.protectionLevel} | ${p.isDangerous ? '⚠️ YES' : 'NO'} | ${p.riskAssessment} |`).join('\n')}

---
`;
  }

  if (options.includeSandbox && analysis.dynamicSandbox) {
    const sb = analysis.dynamicSandbox;
    md += `## 6. Isolated Android Sandbox & Payload Download Interception

- **Virtual OS Environment:** ${sb.environment.osVersion}
- **Device Emulation Model:** ${sb.environment.deviceModel}
- **Dynamic Analysis Verdict:** **${sb.verdict}**
- **Verdict Summary:** ${sb.verdictSummary}
- **Total Network Packets Trapped:** ${sb.totalNetworkRequests}
- **Total Downloaded Files Trapped:** ${sb.downloadedFiles.length}

`;

    if (sb.downloadedFiles.length > 0) {
      md += `### Intercepted File Downloads (${sb.downloadedFiles.length})

| Severity | File Name | Payload Type | Remote URL | Destination Path | Method |
| :--- | :--- | :--- | :--- | :--- | :--- |
${sb.downloadedFiles.map((d) => `| **${d.riskLevel}** | \`${d.fileName}\` | ${d.riskLabel} | \`${d.url}\` | \`${d.destinationPath}\` | ${d.downloadMethod} |`).join('\n')}

#### Detailed Payload Breakdown:
${sb.downloadedFiles.map((d) => `##### [${d.riskLevel}] ${d.fileName} (${d.riskLabel})
- **Download URL:** \`${d.url}\`
- **Target VFS Path:** \`${d.destinationPath}\`
- **Size / MIME:** ${d.fileSizeEstimate} (${d.mimeType})
- **Trigger Component:** \`${d.triggerComponent}\`
- **Behavior Analysis:** ${d.behaviorAnalysis}
- **Mitigation:** ${d.mitigation}
`).join('\n')}
`;
    } else {
      md += `✅ **No secondary file downloads or executable droppers detected during isolated sandbox runtime.**\n\n`;
    }

    md += `---\n`;
  }

  return md;
}
