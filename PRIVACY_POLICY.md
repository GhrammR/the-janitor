# Privacy Policy

**Last Updated:** February 5, 2026

## 1. Introduction

This Privacy Policy describes how The Janitor CLI tool ("we," "our," "the Software") handles your data. We are committed to protecting your privacy and being transparent about our data practices.

**Key Principle:** The Janitor is designed to operate locally on your machine. We do not collect, store, or transmit your source code to our servers.

## 2. Information We Do NOT Collect

The Janitor does **NOT** collect, store, or transmit:

- Your source code or codebase contents
- File names, directory structures, or project metadata
- Usage statistics, analytics, or telemetry
- Personal information (name, email, IP address, etc.)
- Authentication credentials or API keys
- Error reports or crash logs

**We have no servers, no databases, and no tracking infrastructure.**

## 3. Local Data Processing

### 3.1 How the Software Works

The Janitor operates entirely on your local machine or CI/CD environment:

1. **Analysis Phase:** Reads your code files locally to identify dead code
2. **Deletion Phase:** Modifies files on your local filesystem (only when you explicitly run `janitor clean`)
3. **Testing Phase:** Runs your test suite locally to validate changes

All processing happens locally. No data leaves your machine unless you enable optional LLM features (see Section 4).

### 3.2 Temporary Files

The Software may create temporary files on your local filesystem:

- `.janitor_trash/` directory for safely storing deleted files before permanent removal
- Cache files for performance optimization (stored in standard system temp directories)

These files remain on your machine and are managed by you. They are not transmitted to us.

## 4. Optional LLM Features (Semantic Deduplication)

### 4.1 When Data Leaves Your Machine

If you explicitly enable semantic deduplication features using the `janitor dedup` command:

- **Code snippets** (not entire files) may be transmitted to third-party Language Model providers
- This requires you to provide your own API key
- Transmission is **opt-in only** — it does not happen automatically

### 4.2 What Gets Transmitted

When you use LLM features, the following data may be sent to third-party providers:

- **Code snippets:** Small portions of your code (typically 10-50 lines) that the Software identifies as potentially duplicate
- **Function signatures:** Method names, parameter lists, and return types
- **Comments and docstrings:** To help the LLM understand code semantics

**What is NOT transmitted:**

- Your entire codebase or file structure
- Secrets, API keys, or environment variables (unless they appear in the analyzed code snippets)
- Personal information
- Proprietary business logic outside the analyzed snippets

### 4.3 Third-Party LLM Providers

Code snippets are transmitted to third-party LLM API providers as configured by you. Common providers include:

- LLM API aggregators
- Major AI providers
- Custom endpoints (as configured)

**Important:**

- We do not control these third-party services
- They have their own Privacy Policies and Terms of Service
- They may log API requests according to their policies
- You should review their policies before enabling LLM features

### 4.4 Ephemeral Nature of LLM Transmissions

When code is sent to LLM providers:

- **We do not store it** — We have no servers or databases
- **Transmissions are ephemeral** — Data exists only during the API request
- **LLM provider policies apply** — Some providers may log requests for abuse prevention or model improvement

You are responsible for:

- Understanding your LLM provider's data retention policies
- Ensuring compliance with your organization's data policies
- Not enabling LLM features if your code contains sensitive information

## 5. Data Security

### 5.1 Local Security

Since the Software runs locally:

- Your code never leaves your machine (unless you enable LLM features)
- You control all data access through your operating system's permissions
- Standard filesystem security practices apply

### 5.2 LLM Transmission Security

When using LLM features:

- API requests are made over HTTPS (encrypted in transit)
- You are responsible for securing your API keys
- We recommend storing API keys in environment variables or secure key vaults

## 6. Your Data Rights

### 6.1 Access and Control

You have complete control over your data because:

- All processing happens on your machine
- You can inspect the Software's source code (MIT License)
- You can disable LLM features at any time
- You can delete the Software and all associated files

### 6.2 Right to Delete

To delete all data associated with the Software:

1. Delete the Software installation
2. Remove the `.janitor_trash/` directory from your projects
3. Clear any cached data in your system's temp directory

### 6.3 No Data Portability Needed

Since we don't store your data, there is nothing to export or port.

## 7. Cookies and Tracking

The Janitor does not use:

- Cookies
- Tracking pixels
- Analytics scripts
- Fingerprinting techniques
- Any form of user tracking

The Software has no telemetry capabilities.

## 8. Third-Party Links and Services

### 8.1 LLM Providers

When you enable LLM features, you interact directly with third-party services. Each provider has their own Privacy Policy and Terms of Service.

We are not responsible for the privacy practices of these third parties.

### 8.2 GitHub Repository

Our source code is hosted on GitHub. If you interact with our repository (issues, pull requests), GitHub's privacy policy applies:

- **GitHub Privacy Policy:** https://docs.github.com/en/site-policy/privacy-policies

## 9. Children's Privacy

The Janitor is not intended for use by children under 13. We do not knowingly collect data from children. If you are under 13, do not use the Software.

## 10. International Users

The Janitor operates locally on your machine regardless of your location. If you enable LLM features:

- Your data may be transmitted to servers in the United States or other countries
- Different data protection laws may apply
- You are responsible for ensuring compliance with local regulations (e.g., GDPR, CCPA)

### 10.1 GDPR Compliance (EU Users)

For EU users:

- **Data Controller:** You (the user) are the data controller for your source code
- **Data Processor:** LLM providers act as data processors when you enable LLM features
- **Legal Basis:** Your explicit consent when enabling LLM features
- **Right to Object:** You can disable LLM features at any time

## 11. California Privacy Rights (CCPA)

For California residents:

- We do not sell your personal information
- We do not collect personal information through the Software
- If you enable LLM features, you share data directly with third-party providers

## 12. Data Breach Notification

Since we do not collect or store user data:

- We cannot experience a data breach involving your code
- If you use LLM features, contact your LLM provider about their breach notification policies

## 13. Business Transfers

If ownership of the Software changes (acquisition, merger, etc.):

- This Privacy Policy will continue to apply
- No user data will transfer because we don't collect user data
- Premium Wisdom Pack licenses may transfer to the new owner

## 14. Changes to This Policy

We may update this Privacy Policy to reflect:

- Changes in legal requirements
- New features or services
- Improvements to clarity or transparency

Changes will be posted to the GitHub repository with an updated "Last Updated" date. Continued use of the Software after changes constitutes acceptance.

## 15. Your Responsibilities

When using the Software, you are responsible for:

- **Securing your API keys:** Do not commit API keys to version control
- **Reviewing LLM provider policies:** Understand where your data goes if you enable LLM features
- **Compliance with organizational policies:** Ensure use of the Software complies with your employer's data policies
- **Not transmitting sensitive data:** Do not enable LLM features on codebases containing secrets, PII, or regulated data (HIPAA, PCI-DSS, etc.)

## 16. Transparency Commitment

We believe in radical transparency:

- The Software's source code is open source (MIT License)
- You can audit exactly what data is transmitted and when
- We have no hidden telemetry or tracking
- This Privacy Policy is written in plain language

If you have questions about our data practices, please review the source code or contact us.

## 17. Contact Information

For questions about this Privacy Policy, please:

- Open an issue at: https://github.com/GhrammR/the-janitor/issues
- Review the source code at: https://github.com/GhrammR/the-janitor

We will respond to privacy inquiries within 30 days.

---

## Summary (Plain Language)

**What we collect:** Nothing. The Janitor runs locally.

**What gets transmitted:** Only if you enable LLM features, small code snippets go to third-party LLM providers (with your API key). We never see this data.

**Your control:** You control everything. Turn off LLM features anytime. Delete the tool anytime.

**Our commitment:** No tracking, no telemetry, no data collection. Your code is yours.

---

**BY USING THE JANITOR, YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTOOD THIS PRIVACY POLICY.**
