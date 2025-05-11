This project involved a comprehensive vulnerability assessment and penetration testing (VAPT) of a live e-commerce web application named Lifestyle Store. The goal was to identify security flaws in the application using manual testing techniques and industry-standard tools, and to provide a detailed report with actionable remediation guidelines.

The assessment was carried out following the OWASP Top 10 2021 framework, focusing on web application vulnerabilities such as SQL Injection, Cross-Site Scripting, Insecure Direct Object References, Security Misconfigurations, and more.

Scope of Testing:
Frontend and backend modules of the Lifestyle Store web application

Administrative and seller dashboards

Authentication and authorization mechanisms

File upload and download functionalities

Customer data management and payment workflows

Key Vulnerabilities Identified:
1. SQL Injection (Critical)
Multiple endpoints vulnerable to SQLi via unsanitized GET parameters.

Allowed attackers to enumerate databases, dump tables, and retrieve sensitive information.

Exploited using classic ' UNION SELECT payloads to extract user credentials.

2. Reflected & Stored Cross-Site Scripting (XSS) (Severe)
Reflected XSS in search parameters enabled client-side script execution.

Stored XSS in product review fields allowed persistent payload injection.

Enabled phishing attacks and session hijacking via custom JavaScript.

3. Insecure Direct Object Reference (IDOR) (Severe)
Access to user orders, profiles, and reviews was possible by manipulating URL parameters.

Lack of proper authorization controls led to data exposure across users.

4. Insecure File Upload (Critical)
Shell files like .php could be uploaded via admin panel.

Shells were executed to gain server access, execute arbitrary commands, and browse server directories.

5. Rate Limiting Issues (Critical)
OTP brute force vulnerability allowed bypass of password reset authentication.

Admin account takeover was possible by iterating 3-digit OTP values.

6. Command Execution (Critical)
Admin-facing pages allowed direct shell command execution via exposed consoles.

Attackers could execute whoami, manipulate files, and compromise the server OS.

7. Remote File Inclusion (Critical)
Inclusion of external files via URL parameters enabled attacker-controlled PHP script execution.

8. Default Credentials & Exposed Files (Critical)
Use of default admin passwords and public access to userlist.txt led to full seller dashboard access.

9. Client-Side Filter Bypass (Moderate)
Validations were only enforced on the client-side, allowing bypass through intercepted HTTP requests.

10. Directory Listing (Moderate)
Directory browsing enabled on public URLs exposed product images, internal folder structure, and admin panels.

11. Personal Identifiable Information (PII) Leakage (Moderate)
Seller PAN card details and customer shipping info were displayed without proper access restrictions.

12. Open Redirection (Severe)
Redirect parameters could be manipulated to redirect users to malicious third-party domains.

13. Cross-Site Request Forgery (CSRF) (Severe)
Lack of CSRF tokens on password change and cart confirmation actions allowed session hijacking.

14. Coupon Code Brute Force (Severe)
Discount codes could be guessed using simple brute force, leading to financial loss for the business.

15. Forced Browsing (Severe)
Unauthenticated users could directly access sensitive admin dashboards and consoles.

Business Impact:
The vulnerabilities identified posed extremely high risks, including:

Unauthorized access to sensitive customer and seller data.

Full control of server-side operations via shell uploads and command execution.

Brand damage through defacements, phishing, and PII exposure.

Financial losses via coupon abuse, account takeovers, and product manipulation.

Security Recommendations:
Input Validation: Implement server-side input validation using allowlists.

Prepared Statements: Use parameterized queries to prevent SQL injection.

Rate Limiting: Introduce CAPTCHA and lockout mechanisms for repeated failed attempts.

Authentication & Authorization: Implement role-based access control and session management.

CSRF Tokens: Add anti-CSRF tokens to all sensitive forms and actions.

File Upload Restrictions: Restrict to whitelisted extensions and validate file content.

Security Headers: Add X-Content-Type, X-Frame-Options, and CSP headers.

Regular Patch Management: Keep CMS, plugins, and PHP versions up to date.

Access Controls: Hide admin pages, remove default credentials and disable public directory listing.

Outcome:
The assessment was compiled into a professional penetration testing report, complete with:

Technical descriptions of vulnerabilities

Proof-of-Concept (PoC) attacks with screenshots

Business impact analysis

Remediation strategies and OWASP references

The findings were shared with the development team to improve the application’s security posture and reduce the risk of exploitation.# VAPT-ecommerce
