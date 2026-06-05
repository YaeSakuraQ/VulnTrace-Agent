from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


class ScopeValidationError(ValueError):
    """Raised when a task scope or tool target violates policy."""


@dataclass(slots=True)
class ScopeGuard:
    allow_public_targets: bool = False

    def validate_scope(self, scope_entries: list[str]) -> list[str]:
        if not scope_entries:
            raise ScopeValidationError("At least one scope entry is required.")

        normalized: list[str] = []
        for raw_entry in scope_entries:
            entry = raw_entry.strip()
            if not entry:
                continue
            self._validate_entry(entry)
            normalized.append(entry)

        if not normalized:
            raise ScopeValidationError("No valid scope entries were provided.")
        return normalized

    def ensure_target_allowed(self, target: str, scope_entries: list[str]) -> None:
        normalized_scope = self.validate_scope(scope_entries)
        target_ips = self._resolve_target(target)
        for ip_addr in target_ips:
            self._validate_ip(ip_addr)

        for ip_addr in target_ips:
            if self._ip_in_scope(ip_addr, normalized_scope):
                return
        raise ScopeValidationError(f"Target {target} is outside the approved scope.")

    def ensure_targets_allowed(self, targets: list[str], scope_entries: list[str]) -> None:
        for target in targets:
            self.ensure_target_allowed(target, scope_entries)

    def _validate_entry(self, entry: str) -> None:
        if entry == "localhost":
            return
        if "/" in entry:
            network = ipaddress.ip_network(entry, strict=False)
            self._validate_ip(network.network_address)
            if network.is_multicast or network.is_unspecified:
                raise ScopeValidationError(f"Network {entry} is not allowed.")
            return

        try:
            ip_addr = ipaddress.ip_address(entry)
        except ValueError:
            for resolved in self._resolve_target(entry):
                self._validate_ip(resolved)
            return
        self._validate_ip(ip_addr)

    def _resolve_target(self, target: str) -> list[ipaddress._BaseAddress]:
        if target == "localhost":
            return [ipaddress.ip_address("127.0.0.1")]

        try:
            return [ipaddress.ip_address(target)]
        except ValueError:
            pass

        try:
            results = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ScopeValidationError(f"Unable to resolve target {target}: {exc}") from exc

        ips: list[ipaddress._BaseAddress] = []
        for family, _, _, _, sockaddr in results:
            if family == socket.AF_INET:
                ips.append(ipaddress.ip_address(sockaddr[0]))
            elif family == socket.AF_INET6:
                ips.append(ipaddress.ip_address(sockaddr[0]))

        if not ips:
            raise ScopeValidationError(f"Unable to resolve target {target}.")
        return list(dict.fromkeys(ips))

    def _validate_ip(self, ip_addr: ipaddress._BaseAddress) -> None:
        if ip_addr.is_unspecified or ip_addr.is_multicast or ip_addr.is_reserved:
            raise ScopeValidationError(f"Address {ip_addr} is not allowed.")
        if getattr(ip_addr, "is_loopback", False):
            return
        if not self.allow_public_targets and not ip_addr.is_private:
            raise ScopeValidationError(
                f"Public or externally routable address {ip_addr} is not allowed."
            )

    def _ip_in_scope(
        self, ip_addr: ipaddress._BaseAddress, scope_entries: list[str]
    ) -> bool:
        for entry in scope_entries:
            if entry == "localhost" and ip_addr.is_loopback:
                return True
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if ip_addr in network:
                    return True
                continue
            try:
                scoped_ip = ipaddress.ip_address(entry)
            except ValueError:
                if ip_addr in self._resolve_target(entry):
                    return True
                continue
            if ip_addr == scoped_ip:
                return True
        return False
