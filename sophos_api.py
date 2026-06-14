from __future__ import annotations

from copy import deepcopy
from collections.abc import Iterable
from dataclasses import dataclass
import json
import re
import time
import xml.etree.ElementTree as ET

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning


VALID_STATUSES = {"Enable", "Disable"}


class SophosAPIError(RuntimeError):
    pass


class RuleNotFoundError(SophosAPIError):
    pass


class RuleAmbiguousError(SophosAPIError):
    pass


@dataclass(frozen=True)
class RuleStatus:
    name: str
    status: str
    policy_type: str = ""
    ip_family: str = ""
    source_zones: tuple[str, ...] = ()
    source_networks: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return self.status == "Enable"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "enabled": self.enabled,
            "policy_type": self.policy_type,
            "ip_family": self.ip_family,
            "source_zones": list(self.source_zones),
            "source_networks": list(self.source_networks),
        }


@dataclass(frozen=True)
class DeferredRuleUpdate:
    rule_status: RuleStatus
    group_name: str = ""
    group_snapshot_xml: str | None = None


class SophosFirewallClient:
    def __init__(
        self,
        host: str,
        port: str | int,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout: int = 30,
    ) -> None:
        if not host:
            raise ValueError("SFOS_HOST is required")
        if not username:
            raise ValueError("SFOS_USERNAME is required")
        if not password:
            raise ValueError("SFOS_PASSWORD is required")

        self.base_url = f"https://{host}:{port}"
        self.url = f"{self.base_url}/webconsole/APIController"
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()

        if not self.verify_tls:
            urllib3.disable_warnings(InsecureRequestWarning)

    def get_rule_status(self, name: str) -> RuleStatus:
        rule = self._get_rule_element(name)
        return self._rule_status_from_element(rule)

    def set_rule_status(self, name: str, status: str, group_name: str | None = None) -> RuleStatus:
        update = self.set_rule_status_deferred_group_restore(name, status, group_name=group_name)
        if update.group_snapshot_xml:
            self.restore_rule_group_snapshot(update.group_snapshot_xml)
        return self.get_rule_status(name)

    def set_rule_status_via_gui(self, name: str, status: str) -> RuleStatus:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid firewall rule status: {status!r}")

        current = self.get_rule_status(name)
        if current.status == status:
            return current

        session = self._gui_login()
        # The GUI endpoint expects the current state: "1" disables an enabled
        # rule, "-1" enables a disabled rule.
        enable_status = "1" if current.enabled else "-1"
        ip_type = "1" if current.ip_family == "IPv6" else "0"
        payload = {
            "ruleid": self._gui_escaped_name(name),
            "enableStatus": enable_status,
            "mode": 133,
        }
        response = session.get(
            f"{self.base_url}/webconsole/Controller",
            params={
                "mode": "133",
                "json": json.dumps(payload, separators=(",", ":")),
                "ipType": ip_type,
                "__RequestType": "ajax",
                "t": str(int(time.time() * 1000)),
            },
            verify=self.verify_tls,
            timeout=self.timeout,
        )
        data = self._json_response(response, "Sophos Firewall GUI toggle")
        if data.get("status") != 200:
            message = data.get("message") or data.get("opcodeMessage") or "unknown error"
            raise SophosAPIError(f"Sophos Firewall GUI toggle failed: {message}")

        updated = self.get_rule_status(name)
        if updated.status != status:
            raise SophosAPIError(
                f"Sophos Firewall GUI toggle returned success, but {name!r} is still {updated.status}"
            )
        return updated

    def set_rule_status_deferred_group_restore(
        self,
        name: str,
        status: str,
        group_name: str | None = None,
    ) -> DeferredRuleUpdate:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid firewall rule status: {status!r}")

        rule = deepcopy(self._get_rule_element(name))
        preserved_group = self._group_to_preserve(name, group_name, rule)
        status_node = rule.find("./Status")
        if status_node is None:
            raise SophosAPIError(f"Firewall rule {name!r} has no Status node")
        status_node.text = status

        set_node = ET.Element("Set", {"operation": "update"})
        set_node.append(rule)
        root = self._post_xml(self._envelope(set_node))
        self._raise_for_entity_status(root, "FirewallRule")
        return DeferredRuleUpdate(
            rule_status=self._rule_status_from_element(rule),
            group_name=preserved_group.findtext("./Name", "") if preserved_group is not None else "",
            group_snapshot_xml=(
                ET.tostring(preserved_group, encoding="unicode")
                if preserved_group is not None
                else None
            ),
        )

    def restore_rule_group_snapshot(self, group_snapshot_xml: str) -> None:
        try:
            group = ET.fromstring(group_snapshot_xml)
        except ET.ParseError as exc:
            raise SophosAPIError("Stored FirewallRuleGroup snapshot is invalid XML") from exc
        if group.tag != "FirewallRuleGroup":
            raise SophosAPIError("Stored group snapshot is not a FirewallRuleGroup")
        self._post_rule_group_update(group)

    def toggle_rule_status(self, name: str, group_name: str | None = None) -> RuleStatus:
        current = self.get_rule_status(name)
        next_status = "Disable" if current.enabled else "Enable"
        return self.set_rule_status(name, next_status, group_name=group_name)

    def ensure_rule_in_group(self, rule_name: str, group_name: str) -> bool:
        group = self._get_rule_group_element(group_name)
        rule = self._get_rule_element(rule_name)
        changed = self._ensure_security_policy_in_group(group, rule_name, rule)
        if changed:
            self._post_rule_group_update(group)
        return changed

    def rule_is_in_group(self, rule_name: str, group_name: str) -> bool:
        group = self._get_rule_group_element(group_name)
        return self._group_contains_rule(group, rule_name)

    def get_rule_group_memberships(self, rule_names: Iterable[str]) -> dict[str, str]:
        wanted_names = set(rule_names)
        memberships = {}
        if not wanted_names:
            return memberships

        for group in self._get_all_rule_group_elements():
            group_name = group.findtext("./Name", "")
            if not group_name:
                continue
            for security_policy in group.findall("./SecurityPolicyList/SecurityPolicy"):
                rule_name = (security_policy.text or "").strip()
                if rule_name in wanted_names and rule_name not in memberships:
                    memberships[rule_name] = group_name
        return memberships

    def _get_rule_element(self, name: str) -> ET.Element:
        get_node = ET.Element("Get")
        firewall_rule = ET.SubElement(get_node, "FirewallRule")
        filter_node = ET.SubElement(firewall_rule, "Filter")
        key_node = ET.SubElement(filter_node, "key", {"name": "Name", "criteria": "="})
        key_node.text = name

        root = self._post_xml(self._envelope(get_node))
        rules = []
        for rule in root.findall("./FirewallRule"):
            status_node = rule.find("./Status")
            if status_node is not None and status_node.attrib.get("code"):
                self._raise_for_entity_status(root, "FirewallRule")
                continue
            if rule.find("./Name") is None:
                message = status_node.text if status_node is not None else "No rule returned"
                if "zero" in message.lower():
                    raise RuleNotFoundError(f"Firewall rule {name!r} was not found")
                raise SophosAPIError(message)
            rules.append(rule)

        exact_matches = [rule for rule in rules if rule.findtext("./Name", "") == name]
        if not exact_matches:
            raise RuleNotFoundError(f"Firewall rule {name!r} was not found")
        if len(exact_matches) > 1:
            raise RuleAmbiguousError(f"More than one firewall rule matched {name!r}")
        return exact_matches[0]

    def _group_to_preserve(
        self,
        rule_name: str,
        group_name: str | None,
        rule: ET.Element,
    ) -> ET.Element | None:
        if group_name:
            group = deepcopy(self._get_rule_group_element(group_name))
            self._ensure_security_policy_in_group(group, rule_name, rule)
            return group
        group = self._find_rule_group_element_containing(rule_name)
        return deepcopy(group) if group is not None else None

    def _get_rule_group_element(self, name: str) -> ET.Element:
        get_node = ET.Element("Get")
        group = ET.SubElement(get_node, "FirewallRuleGroup")
        filter_node = ET.SubElement(group, "Filter")
        key_node = ET.SubElement(filter_node, "key", {"name": "Name", "criteria": "="})
        key_node.text = name

        root = self._post_xml(self._envelope(get_node))
        groups = []
        for group in root.findall("./FirewallRuleGroup"):
            status_node = group.find("./Status")
            if status_node is not None and status_node.attrib.get("code"):
                self._raise_for_entity_status(root, "FirewallRuleGroup")
                continue
            if group.find("./Name") is None:
                message = status_node.text if status_node is not None else "No group returned"
                if "zero" in message.lower():
                    raise RuleNotFoundError(f"Firewall rule group {name!r} was not found")
                raise SophosAPIError(message)
            groups.append(group)

        exact_matches = [group for group in groups if group.findtext("./Name", "") == name]
        if not exact_matches:
            raise RuleNotFoundError(f"Firewall rule group {name!r} was not found")
        if len(exact_matches) > 1:
            raise RuleAmbiguousError(f"More than one firewall rule group matched {name!r}")
        return exact_matches[0]

    def _find_rule_group_element_containing(self, rule_name: str) -> ET.Element | None:
        for group in self._get_all_rule_group_elements():
            if self._group_contains_rule(group, rule_name):
                return group
        return None

    def _get_all_rule_group_elements(self) -> list[ET.Element]:
        get_node = ET.Element("Get")
        ET.SubElement(get_node, "FirewallRuleGroup")
        root = self._post_xml(self._envelope(get_node))
        groups = []
        for group in root.findall("./FirewallRuleGroup"):
            status_node = group.find("./Status")
            if status_node is not None and status_node.attrib.get("code"):
                self._raise_for_entity_status(root, "FirewallRuleGroup")
                continue
            if group.find("./Name") is not None:
                groups.append(group)
        return groups

    def _group_contains_rule(self, group: ET.Element, rule_name: str) -> bool:
        for security_policy in group.findall("./SecurityPolicyList/SecurityPolicy"):
            if (security_policy.text or "").strip() == rule_name:
                return True
        return False

    def _ensure_security_policy_in_group(
        self,
        group: ET.Element,
        rule_name: str,
        rule: ET.Element | None = None,
    ) -> bool:
        if self._group_contains_rule(group, rule_name):
            return False
        policy_list = group.find("./SecurityPolicyList")
        if policy_list is None:
            policy_list = ET.SubElement(group, "SecurityPolicyList")
        security_policy = ET.Element("SecurityPolicy")
        security_policy.text = rule_name

        insert_index = self._security_policy_insert_index(policy_list, rule)
        if insert_index is None:
            policy_list.append(security_policy)
        else:
            policy_list.insert(insert_index, security_policy)
        return True

    def _security_policy_insert_index(
        self,
        policy_list: ET.Element,
        rule: ET.Element | None,
    ) -> int | None:
        if rule is None:
            return None

        policies = list(policy_list.findall("./SecurityPolicy"))
        position = rule.findtext("./Position", "").strip().lower()
        if position == "top":
            return 0
        if position == "bottom":
            return None

        reference_name = ""
        if position == "after":
            reference_name = rule.findtext("./After/Name", "").strip()
        elif position == "before":
            reference_name = rule.findtext("./Before/Name", "").strip()
        if not reference_name:
            return None

        for index, policy in enumerate(policies):
            if (policy.text or "").strip() == reference_name:
                return index + 1 if position == "after" else index
        return None

    def _post_rule_group_update(self, group: ET.Element) -> None:
        set_node = ET.Element("Set", {"operation": "update"})
        set_node.append(deepcopy(group))
        root = self._post_xml(self._envelope(set_node))
        self._raise_for_entity_status(root, "FirewallRuleGroup")

    def _envelope(self, body_node: ET.Element) -> str:
        request = ET.Element("Request")
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        request.append(body_node)
        return ET.tostring(request, encoding="unicode")

    def _post_xml(self, xml_payload: str) -> ET.Element:
        try:
            response = self.session.post(
                self.url,
                data={"reqxml": xml_payload},
                headers={"Accept": "application/xml"},
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SophosAPIError(f"Could not reach Sophos Firewall API: {exc}") from exc

        if response.status_code != 200:
            raise SophosAPIError(f"Sophos Firewall API returned HTTP {response.status_code}")

        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            preview = response.text[:300].replace("\n", " ")
            raise SophosAPIError(f"Sophos Firewall API returned invalid XML: {preview}") from exc

        self._raise_for_login(root)
        self._raise_for_global_status(root)
        return root

    def _gui_login(self) -> requests.Session:
        session = requests.Session()
        session.headers.update(
            {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Referer": f"{self.base_url}/webconsole/webpages/index.jsp",
                "User-Agent": "Mozilla/5.0",
                "X-Requested-With": "XMLHttpRequest",
            }
        )
        try:
            session.get(
                f"{self.base_url}/webconsole/webpages/login.jsp",
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            login_response = session.post(
                f"{self.base_url}/webconsole/Controller",
                data={
                    "mode": "151",
                    "json": json.dumps(
                        {
                            "username": self.username,
                            "password": self.password,
                            "languageid": "1",
                        },
                        separators=(",", ":"),
                    ),
                },
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SophosAPIError(f"Could not reach Sophos Firewall GUI: {exc}") from exc

        login_data = self._json_response(login_response, "Sophos Firewall GUI login")
        if login_data.get("status") != 200:
            raise SophosAPIError(f"Sophos Firewall GUI login failed: {login_data.get('status')}")

        try:
            index_response = session.get(
                f"{self.base_url}/webconsole/webpages/index.jsp",
                verify=self.verify_tls,
                timeout=self.timeout,
            )
            index_response.raise_for_status()
        except requests.RequestException as exc:
            raise SophosAPIError(f"Could not open Sophos Firewall GUI index: {exc}") from exc

        csrf_match = re.search(r"Cyberoam\.c\$rFt0k3n\s*=\s*'([^']+)'", index_response.text)
        if not csrf_match:
            raise SophosAPIError("Sophos Firewall GUI did not return a CSRF token")
        session.headers.update({"X-CSRF-Token": csrf_match.group(1)})

        try:
            session.post(
                f"{self.base_url}/webconsole/refresh-token",
                data="",
                headers={**session.headers, "Content-Type": "application/json"},
                verify=self.verify_tls,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise SophosAPIError(f"Could not refresh Sophos Firewall GUI token: {exc}") from exc

        return session

    def _json_response(self, response: requests.Response, action: str) -> dict[str, object]:
        if response.status_code != 200:
            raise SophosAPIError(f"{action} returned HTTP {response.status_code}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            preview = response.text[:300].replace("\n", " ")
            raise SophosAPIError(f"{action} returned invalid JSON: {preview}") from exc

    def _gui_escaped_name(self, name: str) -> str:
        return name.replace("\\", "\\\\").replace("'", "\\'")

    def _raise_for_login(self, root: ET.Element) -> None:
        login_status = root.findtext("./Login/status")
        if login_status and login_status != "Authentication Successful":
            raise SophosAPIError(f"Sophos Firewall login failed: {login_status}")

    def _raise_for_global_status(self, root: ET.Element) -> None:
        for status_node in root.findall("./Status"):
            code = status_node.attrib.get("code", "")
            if code and not code.startswith("2"):
                raise SophosAPIError(f"Sophos Firewall API error {code}: {status_node.text}")

    def _raise_for_entity_status(self, root: ET.Element, entity_tag: str) -> None:
        found_status = False
        for status_node in root.findall(f"./{entity_tag}/Status"):
            code = status_node.attrib.get("code", "")
            if not code:
                continue
            found_status = True
            if not code.startswith("2"):
                raise SophosAPIError(f"{entity_tag} API error {code}: {status_node.text}")
        if not found_status:
            raise SophosAPIError(f"{entity_tag} update did not return an operation status")

    def _rule_status_from_element(self, rule: ET.Element) -> RuleStatus:
        name = rule.findtext("./Name", "")
        status = rule.findtext("./Status", "")
        if status not in VALID_STATUSES:
            raise SophosAPIError(f"Firewall rule {name!r} has unexpected status {status!r}")
        policy = self._policy_element(rule)
        return RuleStatus(
            name=name,
            status=status,
            policy_type=rule.findtext("./PolicyType", ""),
            ip_family=rule.findtext("./IPFamily", ""),
            source_zones=self._texts(policy, "./SourceZones/Zone", default=("Any",)),
            source_networks=self._texts(policy, "./SourceNetworks/Network", default=("Any",)),
        )

    def _policy_element(self, rule: ET.Element) -> ET.Element:
        policy_type = rule.findtext("./PolicyType", "").strip()
        candidates = {
            "Network": "./NetworkPolicy",
            "User": "./UserPolicy",
            "User/network rule": "./UserPolicy",
            "HTTPBased": "./HTTPBasedPolicy",
        }
        path = candidates.get(policy_type)
        if path:
            policy = rule.find(path)
            if policy is not None:
                return policy
        for path in ("./NetworkPolicy", "./UserPolicy", "./HTTPBasedPolicy"):
            policy = rule.find(path)
            if policy is not None:
                return policy
        return rule

    def _texts(
        self,
        element: ET.Element,
        path: str,
        default: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        values = tuple(
            text
            for text in ((node.text or "").strip() for node in element.findall(path))
            if text
        )
        return values or default
