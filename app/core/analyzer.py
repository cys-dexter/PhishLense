import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from app.core.heuristics import (
    COMMON_MULTI_PART_TLDS,
    HEX_OCTAL_IP_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    KNOWN_SHORTENERS,
    PERCENT_ENCODED_PATTERN,
    PUNYCODE_PREFIX,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    TARGET_BRANDS,
)
from app.models.schemas import (
    FindingDetail,
    RiskLevel,
    SeverityCounts,
    SeverityLevel,
    UrlAnalysisResponse,
    UrlComponents,
)


class UrlAnalyzer:

    def analyze(self, raw_url: str) -> UrlAnalysisResponse:
        sanitized_input = raw_url.strip()
        normalized_url = self._normalize_url(sanitized_input)
        components = self._dissect_url(sanitized_input, normalized_url)
        findings = self._evaluate_heuristics(components)
        risk_score = self._compute_risk_score(findings)
        risk_level = self._determine_risk_level(risk_score)
        severity_counts = self._compute_severity_counts(findings)
        verdict_summary = self._generate_verdict_summary(risk_level, risk_score, findings)
        recommendations = self._generate_recommendations(risk_level, findings)
        current_timestamp = datetime.now(timezone.utc).isoformat()

        return UrlAnalysisResponse(
            url=sanitized_input,
            normalized_url=normalized_url,
            risk_score=risk_score,
            risk_level=risk_level,
            verdict_summary=verdict_summary,
            components=components,
            severity_counts=severity_counts,
            findings=findings,
            recommendations=recommendations,
            scan_timestamp=current_timestamp,
        )

    def _normalize_url(self, raw_url: str) -> str:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
            return f"http://{raw_url}"
        return raw_url

    def _dissect_url(self, raw_url: str, normalized_url: str) -> UrlComponents:
        parsed = urllib.parse.urlsplit(normalized_url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        hostname = parsed.hostname or ""
        hostname = hostname.lower()
        port = str(parsed.port) if parsed.port is not None else None
        path = parsed.path or "/"
        query = parsed.query
        fragment = parsed.fragment
        raw_query_params = urllib.parse.parse_qs(query, keep_blank_values=True)
        query_params: Dict[str, List[str]] = {
            key: values for key, values in raw_query_params.items()
        }

        is_ip = self._check_is_ip_address(hostname)
        subdomain, domain, registered_domain, tld = self._extract_domain_labels(hostname, is_ip)

        return UrlComponents(
            raw_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            netloc=netloc,
            hostname=hostname,
            subdomain=subdomain,
            domain=domain,
            registered_domain=registered_domain,
            tld=tld,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            query_params=query_params,
            is_ip_address=is_ip,
        )

    def _check_is_ip_address(self, hostname: str) -> bool:
        if not hostname:
            return False
        clean_host = hostname.strip("[]")
        if IPV4_PATTERN.match(clean_host):
            return True
        if IPV6_PATTERN.match(clean_host) and ":" in clean_host:
            return True
        if HEX_OCTAL_IP_PATTERN.match(clean_host):
            return True
        return False

    def _extract_domain_labels(self, hostname: str, is_ip: bool) -> Tuple[str, str, str, str]:
        if not hostname or is_ip:
            return "", hostname, hostname, ""

        parts = hostname.split(".")
        if len(parts) == 1:
            return "", parts[0], parts[0], ""

        two_part_tld = ".".join(parts[-2:])
        if len(parts) >= 3 and two_part_tld in COMMON_MULTI_PART_TLDS:
            tld = two_part_tld
            registered_domain = ".".join(parts[-3:])
            domain = parts[-3]
            subdomain = ".".join(parts[:-3])
            return subdomain, domain, registered_domain, tld

        tld = parts[-1]
        registered_domain = ".".join(parts[-2:])
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
        return subdomain, domain, registered_domain, tld

    def _evaluate_heuristics(self, components: UrlComponents) -> List[FindingDetail]:
        findings: List[FindingDetail] = []

        self._check_ip_address_host(components, findings)
        self._check_basic_auth_trick(components, findings)
        self._check_brand_impersonation(components, findings)
        self._check_punycode_and_homoglyphs(components, findings)
        self._check_url_shortener(components, findings)
        self._check_suspicious_tld(components, findings)
        self._check_subdomain_depth(components, findings)
        self._check_hyphen_abuse(components, findings)
        self._check_suspicious_action_keywords(components, findings)
        self._check_insecure_protocol(components, findings)
        self._check_non_standard_port(components, findings)
        self._check_excessive_url_length(components, findings)
        self._check_open_redirect_pattern(components, findings)
        self._check_percent_encoding_abuse(components, findings)

        if not findings:
            findings.append(
                FindingDetail(
                    rule_id="SEC-000",
                    title="Clean Structural Profile",
                    category="Heuristic Baseline",
                    severity=SeverityLevel.INFO,
                    score_impact=0,
                    plain_english_explanation="No deceptive patterns, known obfuscations, or suspicious domain configurations were detected.",
                    technical_detail=f"The inspected address {components.hostname} uses standard naming and normal transport conventions.",
                )
            )

        return findings

    def _check_ip_address_host(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.is_ip_address:
            findings.append(
                FindingDetail(
                    rule_id="RULE-IP-HOST",
                    title="Direct IP Address Destination",
                    category="Host Identification",
                    severity=SeverityLevel.CRITICAL,
                    score_impact=40,
                    plain_english_explanation="The link points directly to a raw numerical IP address rather than a registered, verifiable brand domain name. Legitimate web services virtually never ask customers to log in through raw IP addresses.",
                    technical_detail=f"Host `{components.hostname}` matches numerical IP pattern. Bypasses DNS reputation filtering.",
                )
            )

    def _check_basic_auth_trick(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if "@" in components.raw_url:
            findings.append(
                FindingDetail(
                    rule_id="RULE-AUTH-AT",
                    title="Embedded Userinfo '@' Redirection Trick",
                    category="Syntax Deception",
                    severity=SeverityLevel.CRITICAL,
                    score_impact=35,
                    plain_english_explanation="The address contains an '@' character. Browsers interpret everything before '@' as throwaway login credentials, while silently routing you to the server that follows it. Attackers use this to display trusted names at the front while steering you to a rogue server.",
                    technical_detail="Presence of userinfo delimiter '@' in URL structure enables visual misleading of authority.",
                )
            )

    def _check_brand_impersonation(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        lower_subdomain = components.subdomain.lower()
        lower_path = components.path.lower()
        lower_registered = components.registered_domain.lower()

        for brand, legitimate_domains in TARGET_BRANDS.items():
            brand_in_subdomain = brand in lower_subdomain
            brand_in_path = re.search(rf"\b{re.escape(brand)}\b", lower_path) is not None

            if brand_in_subdomain or brand_in_path:
                is_legit = any(
                    lower_registered == legit or lower_registered.endswith(f".{legit}")
                    for legit in legitimate_domains
                )
                if not is_legit:
                    location_desc = "subdomain" if brand_in_subdomain else "directory path"
                    findings.append(
                        FindingDetail(
                            rule_id=f"RULE-IMPERSONATE-{brand.upper()}",
                            title=f"Brand Mimicry: {brand.capitalize()}",
                            category="Brand Spoofing",
                            severity=SeverityLevel.CRITICAL,
                            score_impact=35,
                            plain_english_explanation=f"This address places the high-profile brand '{brand}' in its {location_desc}, but the authoritative domain actually belongs to '{components.registered_domain}'. Attackers do this to create a false sense of security.",
                            technical_detail=f"Keyword '{brand}' detected in {location_desc}, but registered authority is '{components.registered_domain}' instead of genuine '{legitimate_domains[0]}'.",
                        )
                    )

    def _check_punycode_and_homoglyphs(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        has_punycode = PUNYCODE_PREFIX in components.hostname
        has_non_ascii = any(ord(char) > 127 for char in components.hostname)

        if has_punycode or has_non_ascii:
            findings.append(
                FindingDetail(
                    rule_id="RULE-HOMOGLYPH-IDN",
                    title="Punycode / Homoglyph Domain Obfuscation",
                    category="Internationalized Domain Deception",
                    severity=SeverityLevel.HIGH,
                    score_impact=25,
                    plain_english_explanation="The domain uses Punycode or non-Latin internationalized characters that look identical or nearly identical to standard English letters (such as Cyrillic 'a' or Greek 'o'). This is a classic homograph attack meant to visually spoof a trusted brand.",
                    technical_detail=f"Hostname contains Punycode prefix '{PUNYCODE_PREFIX}' or non-ASCII characters: `{components.hostname}`.",
                )
            )

    def _check_url_shortener(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.registered_domain in KNOWN_SHORTENERS or components.hostname in KNOWN_SHORTENERS:
            findings.append(
                FindingDetail(
                    rule_id="RULE-SHORTENER",
                    title="Opaque URL Shortener Service",
                    category="Destination Concealment",
                    severity=SeverityLevel.MEDIUM,
                    score_impact=15,
                    plain_english_explanation="This link routes through a URL shortening service that masks its true destination. Attackers frequently utilize shorteners to bypass automated link scanners and hide deceptive domains until clicked.",
                    technical_detail=f"Host `{components.hostname}` matches recognized URL shortening infrastructure.",
                )
            )

    def _check_suspicious_tld(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.tld in SUSPICIOUS_TLDS:
            findings.append(
                FindingDetail(
                    rule_id="RULE-ABUSE-TLD",
                    title=f"High-Risk Top-Level Domain (.{components.tld})",
                    category="Reputation Anomalies",
                    severity=SeverityLevel.MEDIUM,
                    score_impact=15,
                    plain_english_explanation=f"The domain ends with '.{components.tld}', a top-level extension with historically disproportionate rates of spam, bulletproof hosting, and malicious registrations due to low registry oversight.",
                    technical_detail=f"TLD '.{components.tld}' is cataloged in cyber threat feeds for elevated abuse frequency.",
                )
            )

    def _check_subdomain_depth(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.subdomain:
            labels = components.subdomain.split(".")
            if len(labels) >= 3:
                findings.append(
                    FindingDetail(
                        rule_id="RULE-DEEP-SUBDOMAIN",
                        title="Excessive Subdomain Stacking",
                        category="Structural Obfuscation",
                        severity=SeverityLevel.MEDIUM,
                        score_impact=15,
                        plain_english_explanation="The address contains an unusually high number of subdomain layers. Phishing campaigns chain together multiple subdomains to bury the true destination and trick mobile browser address bars.",
                        technical_detail=f"Subdomain contains {len(labels)} nested levels (`{components.subdomain}`). Normal services rarely exceed 1 or 2.",
                    )
                )

    def _check_hyphen_abuse(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        hyphen_count = components.hostname.count("-")
        if hyphen_count >= 2:
            findings.append(
                FindingDetail(
                    rule_id="RULE-EXCESSIVE-HYPHENS",
                    title="Suspicious Domain Hyphenation",
                    category="Domain Naming Patterns",
                    severity=SeverityLevel.HIGH,
                    score_impact=20,
                    plain_english_explanation=f"The host name includes {hyphen_count} hyphens. Attackers frequently stitch trust words together with hyphens (e.g., 'secure-login-account-update') because the clean legitimate domain name is already taken.",
                    technical_detail=f"Domain `{components.hostname}` contains {hyphen_count} hyphen delimiters.",
                )
            )

    def _check_suspicious_action_keywords(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        searchable_text = f"{components.hostname} {components.path} {components.query}".lower()
        matched_keywords = [
            kw for kw in SUSPICIOUS_KEYWORDS
            if re.search(rf"\b{re.escape(kw)}\b", searchable_text)
        ]

        if len(matched_keywords) >= 3:
            findings.append(
                FindingDetail(
                    rule_id="RULE-CREDENTIAL-HARVEST-HIGH",
                    title="Multiple Urgent Credential Traps",
                    category="Behavioral Lure",
                    severity=SeverityLevel.HIGH,
                    score_impact=20,
                    plain_english_explanation=f"The link aggregates multiple urgent security and authentication triggers ({', '.join(matched_keywords[:4])}). This strongly correlates with fake login forms designed to harvest passwords or financial credentials.",
                    technical_detail=f"Detected high density of targeted keywords: {', '.join(matched_keywords)}.",
                )
            )
        elif len(matched_keywords) in (1, 2) and (components.is_ip_address or components.tld in SUSPICIOUS_TLDS or "-" in components.hostname):
            findings.append(
                FindingDetail(
                    rule_id="RULE-CREDENTIAL-HARVEST-MED",
                    title="Authentication Keyword on Non-Standard Domain",
                    category="Behavioral Lure",
                    severity=SeverityLevel.MEDIUM,
                    score_impact=10,
                    plain_english_explanation=f"The keyword '{matched_keywords[0]}' appears in an address that already exhibits atypical infrastructure traits, indicating a potential fake login landing page.",
                    technical_detail=f"Sensitive term '{matched_keywords[0]}' coupled with secondary structural flags.",
                )
            )

    def _check_insecure_protocol(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.scheme == "http":
            has_auth_context = any(
                kw in components.path.lower() or kw in components.query.lower()
                for kw in ("login", "signin", "auth", "account", "verify", "password")
            )
            severity = SeverityLevel.HIGH if has_auth_context else SeverityLevel.MEDIUM
            impact = 20 if has_auth_context else 10
            findings.append(
                FindingDetail(
                    rule_id="RULE-INSECURE-HTTP",
                    title="Unencrypted Cleartext HTTP Protocol",
                    category="Transport Security",
                    severity=severity,
                    score_impact=impact,
                    plain_english_explanation="This site communicates over plain, unencrypted HTTP rather than modern HTTPS. Any data, passwords, or personal details you type into this page can be intercepted or altered by anyone on the same network.",
                    technical_detail=f"Scheme is `{components.scheme}://`. Modern commercial and authentication portals strictly enforce HTTPS.",
                )
            )

    def _check_non_standard_port(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        if components.port and components.port not in ("80", "443"):
            findings.append(
                FindingDetail(
                    rule_id="RULE-NONSTANDARD-PORT",
                    title=f"Non-Standard Service Port (:{components.port})",
                    category="Network Configuration",
                    severity=SeverityLevel.HIGH,
                    score_impact=20,
                    plain_english_explanation=f"The link forces your connection through network port {components.port} instead of standard web traffic ports (80 or 443). Cybercriminals run rogue web applications on unusual ports to bypass basic corporate proxy filters.",
                    technical_detail=f"Explicit destination port `{components.port}` overrides standard protocol ports.",
                )
            )

    def _check_excessive_url_length(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        url_len = len(components.raw_url)
        if url_len > 120:
            findings.append(
                FindingDetail(
                    rule_id="RULE-LENGTH-HIGH",
                    title="Abnormally Long Obfuscated URL",
                    category="Evasion Technique",
                    severity=SeverityLevel.HIGH,
                    score_impact=20,
                    plain_english_explanation=f"At {url_len} characters, this URL is unusually bloated. Threat actors generate massive strings to push the actual host out of mobile address bars or pack encoded payloads into URL parameters.",
                    technical_detail=f"Total character length is {url_len} (critical threshold > 120).",
                )
            )
        elif url_len > 75:
            findings.append(
                FindingDetail(
                    rule_id="RULE-LENGTH-MED",
                    title="Elevated URL Length",
                    category="Evasion Technique",
                    severity=SeverityLevel.LOW,
                    score_impact=5,
                    plain_english_explanation=f"The URL spans {url_len} characters. While complex legitimate query strings exist, phishing campaigns frequently leverage lengthy strings for parameter padding.",
                    technical_detail=f"Total character length is {url_len} (exceeds typical 75 character baseline).",
                )
            )

    def _check_open_redirect_pattern(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        path_query = f"{components.path}?{components.query}"
        has_double_slash = "//" in components.path
        has_embedded_http = (
            "http://" in path_query or "https://" in path_query
        )

        if has_double_slash or has_embedded_http:
            findings.append(
                FindingDetail(
                    rule_id="RULE-OPEN-REDIRECT",
                    title="Embedded Secondary URL / Open Redirect Pattern",
                    category="Navigation Manipulation",
                    severity=SeverityLevel.HIGH,
                    score_impact=20,
                    plain_english_explanation="A secondary web address or double slash appears buried inside the link's directory path or query string. This is frequently used to bounce victims through a legitimate site before redirecting them to a hostile destination.",
                    technical_detail="Detected nested protocol prefixes or double forward slashes inside path/query segments.",
                )
            )

    def _check_percent_encoding_abuse(self, components: UrlComponents, findings: List[FindingDetail]) -> None:
        encoded_matches = PERCENT_ENCODED_PATTERN.findall(components.raw_url)
        if len(encoded_matches) >= 4:
            findings.append(
                FindingDetail(
                    rule_id="RULE-HEX-ENCODING",
                    title="Heavy Percent / Hex Obfuscation",
                    category="Content Obfuscation",
                    severity=SeverityLevel.MEDIUM,
                    score_impact=15,
                    plain_english_explanation=f"The link contains {len(encoded_matches)} percent-encoded hex sequences (%XX). Attackers encode alphanumeric characters to prevent basic security scanners and human reviewers from recognizing malicious terms.",
                    technical_detail=f"Detected {len(encoded_matches)} instances of `%[0-9a-fA-F]{{2}}` encoding.",
                )
            )

    def _compute_risk_score(self, findings: List[FindingDetail]) -> int:
        total_score = sum(f.score_impact for f in findings)
        return min(max(total_score, 0), 100)

    def _determine_risk_level(self, risk_score: int) -> RiskLevel:
        if risk_score >= 66:
            return RiskLevel.DANGEROUS
        if risk_score >= 36:
            return RiskLevel.SUSPICIOUS
        if risk_score >= 16:
            return RiskLevel.LOW_RISK
        return RiskLevel.SAFE

    def _compute_severity_counts(self, findings: List[FindingDetail]) -> SeverityCounts:
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        medium_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
        info_count = sum(1 for f in findings if f.severity == SeverityLevel.INFO)

        return SeverityCounts(
            critical=critical_count,
            high=high_count,
            medium=medium_count,
            low=low_count,
            info=info_count,
        )

    def _generate_verdict_summary(self, risk_level: RiskLevel, risk_score: int, findings: List[FindingDetail]) -> str:
        if risk_level == RiskLevel.DANGEROUS:
            critical_names = [f.title for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)]
            key_reasons = ", ".join(critical_names[:2]) if critical_names else "severe structural anomalies"
            return f"Extreme risk detected (Score: {risk_score}/100). This URL exhibits deceptive characteristics including {key_reasons}. Engaging with this link is strongly inadvisable."

        if risk_level == RiskLevel.SUSPICIOUS:
            reasons = [f.title for f in findings if f.severity in (SeverityLevel.HIGH, SeverityLevel.MEDIUM)]
            key_reasons = ", ".join(reasons[:2]) if reasons else "suspicious naming conventions"
            return f"Caution advised (Score: {risk_score}/100). The analyzed link displays questionable patterns such as {key_reasons}. Verify the authentic source before proceeding."

        if risk_level == RiskLevel.LOW_RISK:
            return f"Minor anomalies found (Score: {risk_score}/100). While no severe deception flags were triggered, proceed with standard digital caution."

        return f"Clean profile verified (Score: {risk_score}/100). No known phishing, homoglyph, or brand spoofing patterns were detected in the structural components."

    def _generate_recommendations(self, risk_level: RiskLevel, findings: List[FindingDetail]) -> List[str]:
        recommendations: List[str] = []

        if risk_level == RiskLevel.DANGEROUS:
            recommendations.append("DO NOT click or open this link in your web browser.")
            recommendations.append("Never enter usernames, passwords, or credit card details on this destination.")
            recommendations.append("If received via email, SMS, or direct message, mark the communication as phishing or spam.")
            recommendations.append("If you have already entered credentials on this site, immediately reset your password on the genuine official website.")
        elif risk_level == RiskLevel.SUSPICIOUS:
            recommendations.append("Do not enter sensitive financial or account credentials.")
            recommendations.append("Manually navigate to the official website by typing the known legitimate address into your browser.")
            recommendations.append("Double-check the exact domain spelling in your browser address bar.")
        elif risk_level == RiskLevel.LOW_RISK:
            recommendations.append("Verify the website has a valid SSL certificate before inputting personal details.")
            recommendations.append("Confirm the context and sender of the link before downloading any files.")
        else:
            recommendations.append("The structural inspection did not identify malicious hallmarks.")
            recommendations.append("Always verify that HTTPS remains active throughout your entire browsing session.")

        return recommendations
