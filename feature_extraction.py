import re
import requests
from urllib.parse import urlparse
from html.parser import HTMLParser


# ---------------------------------------------------------
# HTML parser
# ---------------------------------------------------------

class PageParser(HTMLParser):

    def __init__(self):
        super().__init__()

        self.links = []
        self.scripts = []
        self.forms = []
        self.iframes = []
        self.has_favicon = False
        self.has_mouseover = False
        self.has_right_click = False
        self.has_popup = False
        self.has_mailto = False

    def handle_starttag(self, tag, attrs):

        attrs_dict = dict(attrs)

        if tag == "a":
            href = attrs_dict.get("href", "")
            self.links.append(href)

        if tag == "script":
            self.scripts.append(attrs_dict)

        if tag == "form":
            action = attrs_dict.get("action", "")
            self.forms.append(action)

        if tag == "iframe":
            self.iframes.append(attrs_dict)

        if tag == "link":
            rel = attrs_dict.get("rel", "")
            href = attrs_dict.get("href", "")

            if "icon" in rel.lower() or "favicon" in href.lower():
                self.has_favicon = True

        if "onmouseover" in attrs_dict:
            self.has_mouseover = True

        if "oncontextmenu" in attrs_dict:
            self.has_right_click = True

        if "onclick" in attrs_dict:
            onclick = attrs_dict.get("onclick", "")

            if "window.open" in onclick.lower():
                self.has_popup = True

        if "mailto:" in str(attrs_dict).lower():
            self.has_mailto = True


# ---------------------------------------------------------
# URL helper
# ---------------------------------------------------------

def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def get_domain(url):

    parsed = urlparse(normalize_url(url))

    return parsed.netloc.lower().split(":")[0]


# ---------------------------------------------------------
# 1. having_IP_Address
# ---------------------------------------------------------

def having_ip_address(url):

    domain = get_domain(url)

    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    return 1 if re.match(pattern, domain) else -1


# ---------------------------------------------------------
# 2. URL_Length
# ---------------------------------------------------------

def url_length(url):

    length = len(url)

    if length < 54:
        return 1

    elif length < 75:
        return 0

    else:
        return -1


# ---------------------------------------------------------
# 3. Shortining_Service
# ---------------------------------------------------------

def shortening_service(url):

    domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "tiny.cc",
        "shorturl.at"
    ]

    url_lower = url.lower()

    for domain in domains:

        if domain in url_lower:
            return -1

    return 1


# ---------------------------------------------------------
# 4. having_At_Symbol
# ---------------------------------------------------------

def having_at_symbol(url):

    return -1 if "@" in url else 1


# ---------------------------------------------------------
# 5. double_slash_redirecting
# ---------------------------------------------------------

def double_slash_redirecting(url):

    parsed = urlparse(normalize_url(url))

    if "//" in parsed.path:
        return -1

    return 1


# ---------------------------------------------------------
# 6. Prefix_Suffix
# ---------------------------------------------------------

def prefix_suffix(url):

    domain = get_domain(url)

    return -1 if "-" in domain else 1


# ---------------------------------------------------------
# 7. having_Sub_Domain
# ---------------------------------------------------------

def having_sub_domain(url):

    domain = get_domain(url)

    domain = domain.replace("www.", "")

    parts = domain.split(".")

    if len(parts) <= 2:
        return 1

    elif len(parts) == 3:
        return 0

    else:
        return -1


# ---------------------------------------------------------
# 8. SSLfinal_State
# ---------------------------------------------------------

def ssl_final_state(url):

    if url.lower().startswith("https://"):
        return 1

    return -1


# ---------------------------------------------------------
# 9. Domain_registration_length
# ---------------------------------------------------------

def domain_registration_length(url):

    # Requires WHOIS/domain-registration information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 10. Favicon
# ---------------------------------------------------------

def favicon(url, parser):

    return 1 if parser.has_favicon else -1


# ---------------------------------------------------------
# 11. Port
# ---------------------------------------------------------

def port(url):

    parsed = urlparse(normalize_url(url))

    try:

        p = parsed.port

        if p is None:
            return 1

        if p in [80, 443]:
            return 1

        return -1

    except ValueError:

        return -1


# ---------------------------------------------------------
# 12. HTTPS_token
# ---------------------------------------------------------

def https_token(url):

    domain = get_domain(url)

    if "https" in domain:
        return -1

    return 1


# ---------------------------------------------------------
# 13. Request_URL
# ---------------------------------------------------------

def request_url(url, parser):

    if not parser.links:
        return -1

    external = 0

    domain = get_domain(url)

    for link in parser.links:

        if link.startswith(("http://", "https://")):

            link_domain = get_domain(link)

            if link_domain and link_domain != domain:
                external += 1

    if external == 0:
        return 1

    ratio = external / max(len(parser.links), 1)

    if ratio > 0.5:
        return -1

    return 0


# ---------------------------------------------------------
# 14. URL_of_Anchor
# ---------------------------------------------------------

def url_of_anchor(url, parser):

    if not parser.links:
        return -1

    suspicious = 0

    for link in parser.links:

        if link.startswith("#"):
            suspicious += 1

        elif link.lower().startswith("javascript:"):
            suspicious += 1

    ratio = suspicious / max(len(parser.links), 1)

    if ratio > 0.67:
        return -1

    elif ratio > 0.33:
        return 0

    return 1


# ---------------------------------------------------------
# 15. Links_in_tags
# ---------------------------------------------------------

def links_in_tags(url, parser):

    count = len(parser.links)

    if count == 0:
        return -1

    if count < 20:
        return 1

    elif count < 50:
        return 0

    return -1


# ---------------------------------------------------------
# 16. SFH
# ---------------------------------------------------------

def sfh(url, parser):

    if not parser.forms:
        return 1

    domain = get_domain(url)

    for action in parser.forms:

        if not action:
            continue

        if action.lower() == "about:blank":
            return -1

        if action.startswith(("http://", "https://")):

            action_domain = get_domain(action)

            if action_domain and action_domain != domain:
                return -1

    return 1


# ---------------------------------------------------------
# 17. Submitting_to_email
# ---------------------------------------------------------

def submitting_to_email(url, parser):

    if parser.has_mailto:
        return -1

    return 1


# ---------------------------------------------------------
# 18. Abnormal_URL
# ---------------------------------------------------------

def abnormal_url(url):

    parsed = urlparse(normalize_url(url))

    if parsed.netloc:
        return 1

    return -1


# ---------------------------------------------------------
# 19. Redirect
# ---------------------------------------------------------

def redirect(url):

    parsed = urlparse(normalize_url(url))

    if len(parsed.path.split("/")) > 5:
        return 0

    return 1


# ---------------------------------------------------------
# 20. on_mouseover
# ---------------------------------------------------------

def on_mouseover(url, parser):

    return -1 if parser.has_mouseover else 1


# ---------------------------------------------------------
# 21. RightClick
# ---------------------------------------------------------

def right_click(url, parser):

    return -1 if parser.has_right_click else 1


# ---------------------------------------------------------
# 22. popUpWidnow
# ---------------------------------------------------------

def popup_window(url, parser):

    return -1 if parser.has_popup else 1


# ---------------------------------------------------------
# 23. Iframe
# ---------------------------------------------------------

def iframe(url, parser):

    return -1 if parser.iframes else 1


# ---------------------------------------------------------
# 24. age_of_domain
# ---------------------------------------------------------

def age_of_domain(url):

    # Requires WHOIS/domain information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 25. DNSRecord
# ---------------------------------------------------------

def dns_record(url):

    # Basic DNS availability check using hostname.

    domain = get_domain(url)

    try:

        import socket

        socket.gethostbyname(domain)

        return 1

    except:

        return -1


# ---------------------------------------------------------
# 26. web_traffic
# ---------------------------------------------------------

def web_traffic(url):

    # Requires external traffic ranking information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 27. Page_Rank
# ---------------------------------------------------------

def page_rank(url):

    # Requires external PageRank information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 28. Google_Index
# ---------------------------------------------------------

def google_index(url):

    # Requires search engine index information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 29. Links_pointing_to_page
# ---------------------------------------------------------

def links_pointing_to_page(url):

    # Requires external backlink information.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# 30. Statistical_report
# ---------------------------------------------------------

def statistical_report(url):

    # Requires external reputation databases.
    # Prototype default.

    return 1


# ---------------------------------------------------------
# MAIN FEATURE EXTRACTION
# ---------------------------------------------------------

def extract_features(url):

    url = normalize_url(url)

    parser = PageParser()

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            },
            allow_redirects=True
        )

        html = response.text[:100000]

        parser.feed(html)

    except:

        pass

    features = [

        having_ip_address(url),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(url),
        having_sub_domain(url),
        ssl_final_state(url),
        domain_registration_length(url),
        favicon(url, parser),
        port(url),
        https_token(url),
        request_url(url, parser),
        url_of_anchor(url, parser),
        links_in_tags(url, parser),
        sfh(url, parser),
        submitting_to_email(url, parser),
        abnormal_url(url),
        redirect(url),
        on_mouseover(url, parser),
        right_click(url, parser),
        popup_window(url, parser),
        iframe(url, parser),
        age_of_domain(url),
        dns_record(url),
        web_traffic(url),
        page_rank(url),
        google_index(url),
        links_pointing_to_page(url),
        statistical_report(url)

    ]

    return features


# ---------------------------------------------------------
# Suspicious reasons
# ---------------------------------------------------------

def get_suspicious_reasons(url):

    reasons = []

    if having_ip_address(url) == 1:
        reasons.append("IP address is used instead of a normal domain.")

    if url_length(url) == -1:
        reasons.append("The URL is unusually long.")

    if shortening_service(url) == -1:
        reasons.append("A URL shortening service is detected.")

    if having_at_symbol(url) == -1:
        reasons.append("The URL contains an @ symbol.")

    if double_slash_redirecting(url) == -1:
        reasons.append("Suspicious double-slash redirection pattern detected.")

    if prefix_suffix(url) == -1:
        reasons.append("A hyphen is present in the domain name.")

    if having_sub_domain(url) == -1:
        reasons.append("Multiple subdomains are present.")

    if not url.lower().startswith("https://"):
        reasons.append("The URL does not use HTTPS.")

    return reasons
# =========================================================
# WEBSITE INFORMATION
# =========================================================

def get_website_information(url):

    try:

        # Normalize URL
        url = normalize_url(url)

        # Send request to website
        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/120.0 Safari/537.36"
                )
            }
        )

        # Parse webpage
        parser = PageParser()

        parser.feed(
            response.text[:100000]
        )

        # -------------------------------------------------
        # WEBSITE NAME
        # -------------------------------------------------

        website_name = ""

        # Try to get title from HTML
        title_match = re.search(
            r"<title[^>]*>(.*?)</title>",
            response.text,
            re.IGNORECASE | re.DOTALL
        )

        if title_match:

            website_name = re.sub(
                r"\s+",
                " ",
                title_match.group(1)
            ).strip()

        # If title is unavailable, use domain
        if not website_name:

            website_name = get_domain(url)

        # -------------------------------------------------
        # WEBSITE TYPE
        # -------------------------------------------------

        domain = get_domain(url).lower()

        if any(
            word in domain
            for word in [
                "google",
                "bing",
                "yahoo",
                "duckduckgo"
            ]
        ):

            website_type = "Search Engine"

        elif any(
            word in domain
            for word in [
                "facebook",
                "instagram",
                "twitter",
                "linkedin",
                "reddit"
            ]
        ):

            website_type = "Social Media"

        elif any(
            word in domain
            for word in [
                "youtube",
                "netflix",
                "spotify"
            ]
        ):

            website_type = "Entertainment / Media"

        elif any(
            word in domain
            for word in [
                "amazon",
                "flipkart",
                "ebay"
            ]
        ):

            website_type = "E-Commerce"

        elif any(
            word in domain
            for word in [
                "wikipedia",
                "britannica"
            ]
        ):

            website_type = "Information / Knowledge"

        else:

            website_type = "Website"

        # -------------------------------------------------
        # DESCRIPTION
        # -------------------------------------------------

        description = ""

        description_match = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
            response.text,
            re.IGNORECASE | re.DOTALL
        )

        if description_match:

            description = re.sub(
                r"\s+",
                " ",
                description_match.group(1)
            ).strip()

        # If description is unavailable
        if not description:

            description = (
                f"{website_name} is a website "
                f"available on the internet."
            )

        return {
            "name": website_name,
            "type": website_type,
            "description": description
        }

    except Exception:

        return {
            "name": get_domain(url),
            "type": "Website",
            "description": (
                "Website information could not "
                "be retrieved."
            )
        }