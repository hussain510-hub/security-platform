import pandas as pd

# ── Load risk_engine output ──────────────────────────────────────────────────
df = pd.read_csv('../output/risk_report.csv')

# ── STRIDE mapping (every service name from your real data) ──────────────────
stride_map = {
    # AWS broad
    'aws':                'Spoofing, Tampering, Information Disclosure',

    # Compute
    'ec2':                'Spoofing, Elevation of Privilege',
    'EC2':                'Spoofing, Elevation of Privilege',
    'ebs':                'Tampering, Information Disclosure',
    'Lambda':             'Elevation of Privilege',

    # Identity & Access
    'iam':                'Spoofing, Elevation of Privilege',
    'IAM':                'Spoofing, Elevation of Privilege',
    'accessanalyzer':     'Elevation of Privilege',
    'IAM Access Analyzer':'Elevation of Privilege',

    # Storage
    'S3':                 'Information Disclosure, Tampering',
    'backup':             'Tampering',
    'ECR':                'Tampering, Information Disclosure',

    # Logging & Audit
    'cloudtrail':         'Repudiation',
    'CloudTrail':         'Repudiation',
    'cloudwatch':         'Repudiation',
    'Logging':            'Repudiation',
    'config':             'Repudiation, Tampering',
    'Config':             'Repudiation, Tampering',

    # Security Services
    'guardduty':          'Information Disclosure',
    'guarduty':           'Information Disclosure',   # typo in real data
    'GuardDuty':          'Information Disclosure',
    'securityhub':        'Information Disclosure',
    'SecurityHub':        'Information Disclosure',
    'SecurityServices':   'Information Disclosure',
    'inspector':          'Information Disclosure',

    # Network
    'vpc':                'Denial of Service, Spoofing',
    'networkfirewall':    'Denial of Service',
    'network':            'Denial of Service, Spoofing',

    # Org / Governance
    'organizations':      'Elevation of Privilege',
    'app':                'Tampering, Elevation of Privilege',
    'generic':            'Information Disclosure',

    # Azure broad
    'azure':              'Spoofing, Tampering, Information Disclosure',

    # Azure Compute & Identity
    'Azure Virtual Machines': 'Spoofing, Elevation of Privilege',
    'vm':                     'Spoofing, Elevation of Privilege',
    'entra':                  'Spoofing, Elevation of Privilege',
    'Azure AD':               'Spoofing, Elevation of Privilege',

    # Azure Monitoring
    'monitor':            'Repudiation',
    'Azure Monitor':      'Repudiation',
    'defender':           'Information Disclosure',
    'Microsoft Defender': 'Information Disclosure',

    # Azure Networking / API
    'Azure API Management': 'Spoofing, Denial of Service',
}

# ── Control mapping (same keys) ──────────────────────────────────────────────
control_map = {
    'aws':                'Enforce SCP policies; enable AWS Organizations guardrails',

    'ec2':                'Restrict SG to known CIDRs; enable IMDSv2; patch OS',
    'EC2':                'Restrict SG to known CIDRs; enable IMDSv2; patch OS',
    'ebs':                'Encrypt all EBS volumes at rest; enforce backup plans',
    'Lambda':             'Apply least-privilege execution role; enable X-Ray tracing',

    'iam':                'Enforce MFA; apply least privilege; rotate access keys',
    'IAM':                'Enforce MFA; apply least privilege; rotate access keys',
    'accessanalyzer':     'Enable IAM Access Analyzer; remediate external access findings',
    'IAM Access Analyzer':'Enable IAM Access Analyzer; remediate external access findings',

    'S3':                 'Set ACL private; enable versioning, MFA delete, and encryption',
    'backup':             'Enable AWS Backup; set vault lock and retention policy',
    'ECR':                'Enable image scanning on push; enforce immutable tags',

    'cloudtrail':         'Enable multi-region trail; encrypt with KMS; enable log validation',
    'CloudTrail':         'Enable multi-region trail; encrypt with KMS; enable log validation',
    'cloudwatch':         'Enable log metric filters; create alarms for critical events',
    'Logging':            'Centralise logs; enforce retention policy; restrict log access',
    'config':             'Enable AWS Config rules; auto-remediate non-compliant resources',
    'Config':             'Enable AWS Config rules; auto-remediate non-compliant resources',

    'guardduty':          'Enable GuardDuty all regions; route findings to Security Hub',
    'guarduty':           'Enable GuardDuty all regions; route findings to Security Hub',
    'GuardDuty':          'Enable GuardDuty all regions; route findings to Security Hub',
    'securityhub':        'Enable Security Hub; integrate GuardDuty, Config, and Inspector',
    'SecurityHub':        'Enable Security Hub; integrate GuardDuty, Config, and Inspector',
    'SecurityServices':   'Enable all Defender/Security services; review dashboard daily',
    'inspector':          'Enable Inspector v2; patch Critical/High CVEs within SLA',

    'vpc':                'Enable VPC Flow Logs; tighten NACLs; audit route tables',
    'networkfirewall':    'Deploy Network Firewall with deny-by-default stateful rules',
    'network':            'Restrict NSG inbound rules; remove wildcard ports and sources',

    'organizations':      'Enforce SCPs at OU level; enable all AWS Org features',
    'app':                'Apply WAF rules; enforce authentication on all endpoints',
    'generic':            'Review finding manually; apply principle of least privilege',

    'azure':              'Enforce Azure Policy; enable Defender for Cloud on all subs',
    'Azure Virtual Machines': 'Enable JIT VM access; apply NSG rules; encrypt OS disks',
    'vm':                     'Enable JIT VM access; apply NSG rules; encrypt OS disks',
    'entra':              'Enforce MFA in Entra ID; enable Conditional Access policies',
    'Azure AD':           'Enforce MFA in Entra ID; enable Conditional Access policies',
    'monitor':            'Enable diagnostic settings on all resources; set alert rules',
    'Azure Monitor':      'Enable diagnostic settings on all resources; set alert rules',
    'defender':           'Enable Microsoft Defender plan for all resource types',
    'Microsoft Defender': 'Enable Microsoft Defender plan for all resource types',
    'Azure API Management': 'Enable API gateway auth; apply rate limiting and WAF policy',
}

# ── Threat likelihood from existing Risk Level ────────────────────────────────
likelihood_map = {
    'Critical': 'Very High',
    'High':     'High',
    'Medium':   'Medium',
    'Low':      'Low',
}

# ── Add three new columns ─────────────────────────────────────────────────────
df['STRIDE_Threats']    = df['Service'].map(stride_map).fillna('Unknown')
df['Linked_Control']    = df['Service'].map(control_map).fillna('Review manually')
df['Threat_Likelihood'] = df['Risk Level'].map(likelihood_map).fillna('Unknown')

# ── Save output ───────────────────────────────────────────────────────────────
df.to_csv('../output/threat_model_report.csv', index=False)

# ── Terminal summary ──────────────────────────────────────────────────────────
print("Threat Model Report")
print("=" * 70)

for service, group in df.groupby('Service'):
    stride   = stride_map.get(service, 'Unknown')
    control  = control_map.get(service, 'Review manually')
    count    = len(group)
    levels   = group['Risk Level'].value_counts().to_dict()
    level_str = ', '.join(f"{k}: {v}" for k, v in levels.items())

    print(f"Service  : {service}")
    print(f"Threats  : {stride}")
    print(f"Control  : {control}")
    print(f"Findings : {count}  ({level_str})")
    print("-" * 70)

# ── Stats summary ─────────────────────────────────────────────────────────────

total       = len(df)
unknown     = (df['STRIDE_Threats'] == 'Unknown').sum()
mapped      = total - unknown
critical    = (df['Risk Level'] == 'Critical').sum()
high        = (df['Risk Level'] == 'High').sum()

print()
print("=" * 70)
print(f"Total findings        : {total}")
print(f"Threats mapped        : {mapped}")
print(f"Unmapped (Unknown)    : {unknown}")
print(f"Critical findings     : {critical}")
print(f"High findings         : {high}")
print("=" * 70)
print("threat_model_report.csv saved to output/")

# ── Stats summary ─────────────────────────────────────────────────────────────
total       = len(df)
unmapped    = (df['STRIDE_Threats'] == 'Unknown').sum()
mapped      = total - unmapped
critical    = (df['Risk Level'] == 'Critical').sum()
high        = (df['Risk Level'] == 'High').sum()
medium      = (df['Risk Level'] == 'Medium').sum()
low         = (df['Risk Level'] == 'Low').sum()

print()
print("=" * 70)
print(f"Total findings        : {total}")
print(f"Threats mapped        : {mapped}  ({round(mapped/total*100, 1)}%)")
print(f"Unmapped (Unknown)    : {unmapped}  ({round(unmapped/total*100, 1)}%)")
print(f"Critical findings     : {critical}")
print(f"High findings         : {high}")
print(f"Medium findings       : {medium}")
print(f"Low findings          : {low}")
print("=" * 70)

# ── STRIDE threat frequency breakdown ────────────────────────────────────────
print("\nSTRIDE Threat Frequency:")
print("-" * 70)
stride_categories = [
    'Spoofing', 'Tampering', 'Repudiation',
    'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'
]
for cat in stride_categories:
    count = df['STRIDE_Threats'].str.contains(cat, na=False).sum()
    bar   = '█' * (count // 100)
    print(f"  {cat:<30} {count:>5}  {bar}")

print()
print("threat_model_report.csv saved to output/")
