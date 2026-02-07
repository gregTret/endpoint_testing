import logging
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from config import HTML_PARSER

log = logging.getLogger(__name__)

# Resolve parser — fall back to stdlib if lxml isn't installed
try:
    import lxml  # noqa: F401
    _PARSER = HTML_PARSER
except ImportError:
    _PARSER = "html.parser"
    log.info("lxml not available, falling back to html.parser")


def extract_links(html: str, base_url: str) -> set[str]:
    """Extract all unique links from an HTML page."""
    soup = BeautifulSoup(html, _PARSER)
    links: set[str] = set()

    for tag in soup.find_all("a", href=True):
        links.add(_normalize(urljoin(base_url, tag["href"])))

    for tag in soup.find_all("form", action=True):
        links.add(_normalize(urljoin(base_url, tag["action"])))

    for tag in soup.find_all("link", href=True):
        links.add(_normalize(urljoin(base_url, tag["href"])))

    for tag in soup.find_all("script", src=True):
        links.add(_normalize(urljoin(base_url, tag["src"])))

    for tag in soup.find_all("img", src=True):
        links.add(_normalize(urljoin(base_url, tag["src"])))

    return links


def extract_forms(html: str, base_url: str) -> list[dict]:
    """Extract form details (action, method, inputs) for injection testing."""
    soup = BeautifulSoup(html, _PARSER)
    forms: list[dict] = []

    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action", ""))
        method = form.get("method", "GET").upper()
        inputs: list[dict] = []

        for inp in form.find_all(["input", "textarea", "select"]):
            info: dict = {
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            }
            if inp.name == "select":
                info["options"] = [
                    opt.get("value", opt.text) for opt in inp.find_all("option")
                ]
            if info["name"]:
                inputs.append(info)

        forms.append({"action": action, "method": method, "inputs": inputs})

    return forms


def filter_same_domain(links: set[str], domain: str) -> set[str]:
    """Keep only links whose host matches *domain*."""
    return {
        link for link in links
        if urlparse(link).netloc == domain or urlparse(link).netloc == ""
    }


def _normalize(url: str) -> str:
    """Strip fragments from a URL."""
    return urlparse(url)._replace(fragment="").geturl()
