from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup


class ParameterExtractor:
    def extract_get_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        if not parsed.query:
            return []
        return list(parse_qs(parsed.query, keep_blank_values=True).keys())

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        soup = BeautifulSoup(html, "html.parser")
        forms: List[Dict] = []

        for form in soup.find_all("form"):
            form_info = self._parse_form(form, base_url)
            if form_info:
                forms.append(form_info)

        return forms

    def _parse_form(self, form, base_url: str) -> Optional[Dict]:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        action_url = urljoin(base_url, action) if action else base_url

        inputs: List[Dict] = []

        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue
            inputs.append(
                {
                    "name": name,
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", ""),
                }
            )

        for textarea in form.find_all("textarea"):
            name = textarea.get("name")
            if not name:
                continue
            inputs.append(
                {
                    "name": name,
                    "type": "textarea",
                    "value": textarea.get_text(),
                }
            )

        for select in form.find_all("select"):
            name = select.get("name")
            if not name:
                continue

            options = select.find_all("option")
            selected = next((opt for opt in options if opt.get("selected")), None)
            default_option = selected or (options[0] if options else None)
            default_value = ""
            if default_option is not None:
                default_value = default_option.get("value", default_option.get_text())

            inputs.append(
                {
                    "name": name,
                    "type": "select",
                    "value": default_value,
                }
            )

        if not inputs:
            return None

        return {
            "action": action_url,
            "method": method,
            "inputs": inputs,
        }

    def extract_all_params(self, url: str, html: Optional[str] = None) -> Dict:
        result = {
            "get_params": self.extract_get_params(url),
            "forms": [],
        }
        if html:
            result["forms"] = self.extract_forms(html, url)
        return result

    def get_testable_params(self, url: str, html: Optional[str] = None) -> List[Dict]:
        test_points: List[Dict] = []

        for param in self.extract_get_params(url):
            test_points.append(
                {
                    "type": "get",
                    "url": url,
                    "param_name": param,
                    "base_data": None,
                }
            )

        if html:
            for form in self.extract_forms(html, url):
                is_get = form["method"].upper() == "GET"
                for field in form["inputs"]:
                    test_points.append(
                        {
                            "type": "get" if is_get else "post",
                            "url": form["action"],
                            "param_name": field["name"],
                            "base_data": None
                            if is_get
                            else self._build_base_data(form["inputs"]),
                        }
                    )

        return test_points

    def _build_base_data(self, inputs: List[Dict]) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for field in inputs:
            data[field["name"]] = field.get("value", "test")
        return data
