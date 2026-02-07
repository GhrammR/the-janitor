# Terms of Service

**Last Updated:** February 5, 2026

## 1. Acceptance of Terms

By downloading, installing, or using The Janitor CLI tool ("the Software"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, do not use the Software.

## 2. Description of Service

The Janitor is a command-line tool for automated dead-code detection and removal. The Software:

- Analyzes your codebase locally to identify unused files and symbols
- Optionally removes dead code after running safety tests
- May transmit code snippets to third-party Language Model APIs for semantic deduplication if you explicitly enable this feature
- Operates entirely on your local machine or within your CI/CD pipeline

## 3. License

### 3.1 Core Software (MIT License)

The core Janitor software is licensed under the MIT License. You may use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the MIT License terms included in the `LICENSE` file.

### 3.2 Premium Wisdom Packs (Proprietary)

Premium Wisdom Packs (framework-specific detection rules) are proprietary and subject to separate licensing terms. Unauthorized distribution, modification, or reverse engineering of Premium Wisdom Packs is prohibited.

## 4. User Responsibilities

### 4.1 Version Control Requirement

**YOU MUST USE VERSION CONTROL (e.g., Git) BEFORE RUNNING THE JANITOR.** The Software modifies or deletes code files. You are solely responsible for:

- Maintaining backups of your code
- Using version control systems to track changes
- Reviewing changes before committing them
- Being able to revert any unwanted modifications

### 4.2 Test Validation

You are responsible for:

- Ensuring your test suite is comprehensive
- Reviewing the Software's analysis results before proceeding with deletion
- Validating that deleted code does not break your application

### 4.3 CI/CD Integration

If you integrate The Janitor into your CI/CD pipeline:

- You are responsible for configuring appropriate safeguards
- You accept all risks associated with automated code modification
- You must ensure proper approvals are in place for production deployments

## 5. No Liability for Code Deletion

**THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

### 5.1 Disclaimer

WE ARE NOT RESPONSIBLE FOR:

- Any code deleted by the Software, whether correctly or incorrectly identified as dead code
- Loss of data, revenue, or business opportunities resulting from code deletion
- Bugs, runtime errors, or application failures caused by code removal
- False positives or false negatives in dead-code detection
- Any damage to your codebase, production systems, or business operations

### 5.2 Assumption of Risk

By using the Software, you explicitly acknowledge and accept that:

- Automated code analysis may produce incorrect results
- The Software may delete code that appears unused but is actually required
- You are solely responsible for validating the Software's recommendations
- You use the Software entirely at your own risk

## 6. Data Collection and Privacy

### 6.1 Local Operation

The Janitor operates primarily on your local machine. We do not:

- Collect, store, or transmit your source code to our servers
- Track your usage patterns or codebase statistics
- Require account creation or authentication for core functionality

### 6.2 Optional LLM Features

If you enable semantic deduplication features:

- Code snippets may be transmitted to third-party LLM providers
- Transmissions are ephemeral and not stored by us
- You are responsible for reviewing your organization's data policies before enabling this feature
- See our Privacy Policy for additional details

### 6.3 Telemetry

The Software does not contain telemetry or analytics. We do not track your usage.

## 7. Third-Party Services

### 7.1 LLM Providers

When using optional LLM features, you interact directly with third-party services:

- Third-party LLM providers as configured by you
- These services have their own Terms of Service and Privacy Policies
- We are not responsible for their data handling, availability, or costs
- You are responsible for obtaining necessary API keys and managing costs

### 7.2 API Keys

You must provide your own API keys for LLM services. You are responsible for:

- Keeping your API keys secure
- Any costs incurred from API usage
- Compliance with the LLM provider's terms of service

## 8. Intellectual Property

### 8.1 Your Code

You retain all rights to your source code. The Software does not claim ownership of:

- Your codebase or any files analyzed by the Software
- Derivative works created through code modification
- Any intellectual property in your projects

### 8.2 Our Software

The Janitor's source code, documentation, and Premium Wisdom Packs are protected by copyright and other intellectual property laws. Except as expressly permitted by the MIT License (for core components), you may not:

- Reverse engineer proprietary components
- Redistribute Premium Wisdom Packs without authorization
- Remove copyright or attribution notices

## 9. Warranty Disclaimer

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

We make no warranties that:

- The Software will meet your requirements
- The Software will be error-free or operate without interruption
- Dead-code detection will be accurate or complete
- Use of the Software will not cause data loss

## 10. Limitation of Liability

**TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

This includes, but is not limited to:

- Direct, indirect, incidental, special, exemplary, or consequential damages
- Loss of profits, data, or business opportunities
- Cost of procurement of substitute goods or services
- Any damages resulting from code deletion or modification

## 11. Indemnification

You agree to indemnify and hold harmless the authors, contributors, and copyright holders from any claims, damages, losses, liabilities, and expenses (including legal fees) arising from:

- Your use of the Software
- Your violation of these Terms
- Your violation of any rights of another party
- Code deletions or modifications made by the Software

## 12. Changes to Terms

We reserve the right to modify these Terms at any time. Changes will be effective immediately upon posting to the repository. Your continued use of the Software after changes constitutes acceptance of the modified Terms.

## 13. Termination

You may stop using the Software at any time by deleting it from your systems. We may terminate or suspend your access to Premium Wisdom Packs at any time without notice if you violate these Terms.

## 14. Governing Law

These Terms shall be governed by and construed in accordance with the laws of the jurisdiction in which the copyright holder resides, without regard to conflict of law principles.

## 15. Severability

If any provision of these Terms is found to be unenforceable or invalid, that provision will be limited or eliminated to the minimum extent necessary, and the remaining provisions will remain in full force and effect.

## 16. Entire Agreement

These Terms, along with the Privacy Policy and applicable licenses, constitute the entire agreement between you and the authors regarding the Software.

## 17. Contact

For questions about these Terms, please open an issue at:
https://github.com/GhrammR/the-janitor/issues

---

**BY USING THE JANITOR, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO BE BOUND BY THESE TERMS OF SERVICE.**
