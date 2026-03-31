#!/usr/bin/env python3
"""Generate synthetic Snowflake SSPM reports without live Snowflake connection."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from snowflake_scanner import (
    Finding, compute_score, print_console_report,
    write_json_report, write_html_report
)

def main():
    account = "demo-xy12345.us-east-1"

    # Build synthetic findings aligned with CIS Snowflake Foundations Benchmark v1.0.0
    findings = [
        # Section 1: Identity and Access Management
        Finding("SF-IAM-001", "SSO is configured for your account", "FAIL", "HIGH",
                description="No SAML or SCIM integration detected. Users authenticate with Snowflake-local passwords only.",
                remediation="Configure SAML 2.0 SSO integration with your corporate IdP (Okta, Azure AD, Ping).",
                evidence="SHOW SECURITY INTEGRATIONS: 0 SAML integrations found.",
                cis_ref="1.1", profile_level=1),
        Finding("SF-IAM-002", "MFA is enabled for all users", "FAIL", "CRITICAL",
                description="12 of 45 users do not have MFA enrolled.",
                remediation="Enable MFA for all human users. Use ALTER USER ... SET RSA_PUBLIC_KEY for service accounts.",
                evidence="Users without MFA: analyst1, analyst2, developer1, marketing1 (+8 more)",
                cis_ref="1.2", profile_level=1),
        Finding("SF-IAM-003", "Minimum password length is 14 characters", "FAIL", "HIGH",
                description="Current minimum password length is 8 characters.",
                remediation="ALTER ACCOUNT SET MIN_PASSWORD_LENGTH = 14.",
                evidence="SHOW PARAMETERS LIKE 'PASSWORD_POLICY': min_length=8",
                cis_ref="1.3", profile_level=1),
        Finding("SF-IAM-004", "Password policy requires mixed case", "PASS", "MEDIUM",
                description="Password policy requires upper and lower case characters.",
                remediation="N/A",
                evidence="PASSWORD_POLICY: upper=1, lower=1",
                cis_ref="1.4", profile_level=1),
        Finding("SF-IAM-005", "Password policy requires special characters", "PASS", "MEDIUM",
                description="Password policy requires at least 1 special character.",
                remediation="N/A",
                evidence="PASSWORD_POLICY: special=1",
                cis_ref="1.5", profile_level=1),
        Finding("SF-IAM-006", "Password policy requires numeric characters", "PASS", "MEDIUM",
                description="Password policy requires at least 1 numeric character.",
                remediation="N/A",
                evidence="PASSWORD_POLICY: numeric=1",
                cis_ref="1.6", profile_level=1),
        Finding("SF-IAM-007", "ACCOUNTADMIN role is limited to < 5 users", "FAIL", "CRITICAL",
                description="7 users have ACCOUNTADMIN role (recommended: <= 4).",
                remediation="Revoke ACCOUNTADMIN from non-essential users. Use least-privilege custom roles.",
                evidence="ACCOUNTADMIN members: admin, dba1, dba2, secops, devlead, data_eng, cto",
                cis_ref="1.7", profile_level=1),
        Finding("SF-IAM-008", "ACCOUNTADMIN is not used for daily operations", "WARN", "HIGH",
                description="3 users used ACCOUNTADMIN role in last 7 days for non-admin queries.",
                remediation="Create task-specific roles. Reserve ACCOUNTADMIN for administrative operations only.",
                evidence="Recent ACCOUNTADMIN queries from: analyst1, developer1, data_eng",
                cis_ref="1.8", profile_level=1),
        Finding("SF-IAM-009", "Custom roles follow least-privilege principle", "FAIL", "HIGH",
                description="2 custom roles have been granted ALL PRIVILEGES on databases.",
                remediation="Review and restrict custom role grants. Remove ALL PRIVILEGES and grant specific permissions.",
                evidence="Roles with ALL PRIVILEGES: POWER_USER, DATA_ADMIN",
                cis_ref="1.9", profile_level=1),
        Finding("SF-IAM-010", "Service accounts use key-pair authentication", "FAIL", "HIGH",
                description="4 service accounts use password authentication instead of key-pair.",
                remediation="Configure RSA key-pair authentication for all service accounts.",
                evidence="Password-auth service accounts: svc_etl, svc_bi, svc_dbt, svc_airflow",
                cis_ref="1.10", profile_level=1),
        Finding("SF-IAM-011", "Stale users disabled or removed", "FAIL", "MEDIUM",
                description="8 users have not logged in for over 90 days.",
                remediation="Disable inactive users with ALTER USER ... SET DISABLED = TRUE.",
                evidence="Stale users: former_contractor1, temp_analyst, intern_2024q1 (+5 more)",
                cis_ref="1.11", profile_level=1),
        Finding("SF-IAM-012", "Role hierarchy follows least-privilege model", "PASS", "MEDIUM",
                description="Role hierarchy does not have excessive cross-grants.",
                remediation="N/A",
                evidence="Role DAG depth: 4, no circular grants detected.",
                cis_ref="1.12", profile_level=2),
        Finding("SF-IAM-013", "SCIM provisioning configured", "FAIL", "MEDIUM",
                description="No SCIM integration for automated user provisioning/deprovisioning.",
                remediation="Configure SCIM integration with your IdP for automated lifecycle management.",
                evidence="SHOW SECURITY INTEGRATIONS TYPE=SCIM: 0 results",
                cis_ref="1.13", profile_level=2),

        # Section 2: Monitoring and Alerting
        Finding("SF-MON-001", "Account-level audit logging enabled", "PASS", "HIGH",
                description="Access history and query history are available in SNOWFLAKE.ACCOUNT_USAGE.",
                remediation="N/A",
                evidence="ACCOUNT_USAGE.ACCESS_HISTORY: accessible, rows > 0",
                cis_ref="2.1", profile_level=1),
        Finding("SF-MON-002", "Login history monitored for anomalies", "FAIL", "HIGH",
                description="No alert or task configured to monitor failed login attempts.",
                remediation="Create a Snowflake task or alert to monitor LOGIN_HISTORY for failed attempts.",
                evidence="SHOW ALERTS: 0 alerts referencing LOGIN_HISTORY",
                cis_ref="2.2", profile_level=1),
        Finding("SF-MON-003", "Query history retention configured", "PASS", "MEDIUM",
                description="Query history is retained for 365 days (Snowflake default).",
                remediation="N/A",
                evidence="QUERY_HISTORY retention: 365 days (default)",
                cis_ref="2.3", profile_level=1),
        Finding("SF-MON-004", "Resource monitors configured", "FAIL", "MEDIUM",
                description="No resource monitors configured to control credit consumption.",
                remediation="Create resource monitors with credit quotas and suspend actions.",
                evidence="SHOW RESOURCE MONITORS: 0 results",
                cis_ref="2.4", profile_level=1),
        Finding("SF-MON-005", "Alerts for privilege escalation", "FAIL", "HIGH",
                description="No monitoring for GRANT ROLE ACCOUNTADMIN or similar privilege escalation.",
                remediation="Create alert on QUERY_HISTORY for GRANT statements involving privileged roles.",
                evidence="No alerts found for privilege escalation patterns.",
                cis_ref="2.5", profile_level=2),
        Finding("SF-MON-006", "Data sharing audit enabled", "WARN", "MEDIUM",
                description="Outbound data shares exist but no monitoring alert is configured.",
                remediation="Create alerts to monitor DATA_SHARING_USAGE for new outbound shares.",
                evidence="Outbound shares: 3, monitoring alerts: 0",
                cis_ref="2.6", profile_level=2),

        # Section 3: Networking
        Finding("SF-NET-001", "Network policy restricts access by IP", "FAIL", "HIGH",
                description="No network policy is configured. Account is accessible from any IP.",
                remediation="Create a network policy with ALLOWED_IP_LIST for corporate/VPN CIDR ranges.",
                evidence="SHOW NETWORK POLICIES: 0 results",
                cis_ref="3.1", profile_level=1),
        Finding("SF-NET-002", "Private connectivity (AWS PrivateLink / Azure Private Link)", "FAIL", "MEDIUM",
                description="No private connectivity configured. All traffic traverses public internet.",
                remediation="Configure AWS PrivateLink or Azure Private Link for private connectivity.",
                evidence="SHOW SECURITY INTEGRATIONS TYPE=PRIVATE_LINK: 0 results",
                cis_ref="3.2", profile_level=2),

        # Section 4: Data Protection
        Finding("SF-DP-001", "Tri-Secret Secure (customer-managed key) enabled", "FAIL", "HIGH",
                description="Tri-Secret Secure is not enabled. Snowflake manages all encryption keys.",
                remediation="Enable Tri-Secret Secure to use customer-managed keys alongside Snowflake keys.",
                evidence="SYSTEM$GET_CUSTOMER_MANAGED_KEY_STATUS: NOT_CONFIGURED",
                cis_ref="4.1", profile_level=2),
        Finding("SF-DP-002", "Column-level masking policies applied", "FAIL", "HIGH",
                description="No dynamic data masking policies found on PII columns.",
                remediation="Apply masking policies on columns containing PII, PHI, or financial data.",
                evidence="SHOW MASKING POLICIES: 0 results",
                cis_ref="4.2", profile_level=1),
        Finding("SF-DP-003", "Row access policies configured", "FAIL", "MEDIUM",
                description="No row access policies configured for multi-tenant or departmental data isolation.",
                remediation="Create row access policies to enforce row-level security on shared tables.",
                evidence="SHOW ROW ACCESS POLICIES: 0 results",
                cis_ref="4.3", profile_level=2),
        Finding("SF-DP-004", "External stages use encrypted connections", "PASS", "HIGH",
                description="All external stages use encryption (ENCRYPTION=REQUIRED or TYPE=AZURE_CSE).",
                remediation="N/A",
                evidence="All 5 external stages have encryption enabled.",
                cis_ref="4.4", profile_level=1),
        Finding("SF-DP-005", "Data classification tags applied", "FAIL", "MEDIUM",
                description="No classification tags (SEMANTIC_CATEGORY, PRIVACY_CATEGORY) applied.",
                remediation="Use Snowflake's data classification to tag sensitive columns.",
                evidence="SELECT * FROM TAG_REFERENCES WHERE TAG_SCHEMA='CLASSIFICATION': 0 rows",
                cis_ref="4.5", profile_level=2),
        Finding("SF-DP-006", "Secure views used for shared data", "WARN", "MEDIUM",
                description="2 of 8 shared views are not marked as SECURE.",
                remediation="Convert shared views to SECURE views to prevent data leakage through query optimization.",
                evidence="Non-secure shared views: analytics.v_customer_360, reporting.v_sales_summary",
                cis_ref="4.6", profile_level=1),
        Finding("SF-DP-007", "Time Travel retention configured appropriately", "PASS", "LOW",
                description="Default TIME_TRAVEL_RETENTION is set to 7 days.",
                remediation="N/A",
                evidence="DATA_RETENTION_TIME_IN_DAYS = 7",
                cis_ref="4.7", profile_level=1),
        Finding("SF-DP-008", "Fail-safe enabled for critical databases", "PASS", "LOW",
                description="Fail-safe is enabled (default) for all Enterprise edition databases.",
                remediation="N/A",
                evidence="Enterprise edition: fail-safe = 7 days (default)",
                cis_ref="4.8", profile_level=1),
    ]

    # Compute score
    score_data = compute_score(findings)

    # Print console report
    print_console_report(findings, score_data, account)

    # Write reports
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out_dir, exist_ok=True)

    json_path = os.path.join(out_dir, "snowflake_sspm_report.json")
    html_path = os.path.join(out_dir, "snowflake_sspm_report.html")

    write_json_report(findings, score_data, account, json_path)
    write_html_report(findings, score_data, account, html_path)

    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] Total findings: {len(findings)}")
    print(f"[+] Score: {score_data['score']}% (Grade: {score_data['grade']})")
    c = score_data['counts']
    print(f"    PASS: {c['PASS']}, FAIL: {c['FAIL']}, WARN: {c['WARN']}, SKIP: {c['SKIP']}")

if __name__ == "__main__":
    main()
