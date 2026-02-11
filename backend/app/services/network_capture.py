"""
SentinelFlow - Real-Time Network Capture Service

Captures actual network packets using Scapy and extracts features
for ML-based intrusion detection.

Note: Requires root/sudo privileges for raw packet capture.
"""

import asyncio
import threading
import time
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from collections import defaultdict
from dataclasses import dataclass, field
import socket
import struct
from loguru import logger

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP,
        get_if_list, get_if_addr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not installed. Network capture will not work.")


def validate_ip_filter(ip: str) -> str:
    """
    Validate and sanitize IP address for use in BPF filter.

    Prevents BPF filter injection attacks by ensuring input is a valid IP.

    Args:
        ip: IP address string to validate

    Returns:
        Validated IP address string

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        # Parse and validate the IP address
        validated = ipaddress.ip_address(ip)
        return str(validated)
    except ValueError as e:
        raise ValueError(f"Invalid IP address for filter: {ip}") from e


@dataclass
class NetworkFlow:
    """Represents a network flow (connection) with features for ML."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_time: float = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0

    @property
    def duration(self) -> float:
        return max(0.001, self.last_time - self.start_time)

    def to_dict(self) -> Dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "timestamp": datetime.fromtimestamp(self.start_time).isoformat(),
            "duration": round(self.duration, 3),
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_ip_bytes": self.resp_ip_bytes,
            "packets_sent": self.orig_pkts,
            "packets_received": self.resp_pkts,
            "bytes_sent": self.orig_bytes,
            "bytes_received": self.resp_bytes,
        }

    def get_ml_features(self) -> Dict:
        """Extract features for ML model input."""
        return {
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_ip_bytes": self.resp_ip_bytes,
            "duration": self.duration,
            "missed_bytes": 0,
            "dst_port": self.dst_port,
            "src_port": self.src_port,
        }


class NetworkCaptureService:
    """
    Real-time network packet capture and flow analysis service.

    Captures packets from specified network interface, aggregates them
    into flows, and provides features for ML-based detection.
    """

    def __init__(self):
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.flows: Dict[str, NetworkFlow] = {}
        self.packets_captured = 0
        self.start_time: Optional[float] = None
        self.duration: int = 60
        self.interface: str = ""
        self.target_filter: str = ""
        self.on_flow_callback: Optional[Callable] = None
        self.on_alert_callback: Optional[Callable] = None
        self._stop_event = threading.Event()
        self._flow_timeout = 30  # seconds before flow is considered complete

    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces."""
        interfaces = []

        if not SCAPY_AVAILABLE:
            return [{"name": "demo", "ip": "127.0.0.1", "description": "Demo mode (scapy not available)"}]

        try:
            for iface in get_if_list():
                try:
                    ip = get_if_addr(iface)
                    if ip and ip != "0.0.0.0":
                        interfaces.append({
                            "name": iface,
                            "ip": ip,
                            "description": f"{iface} ({ip})"
                        })
                except (OSError, ValueError) as e:
                    # Non-critical interface query error
                    logger.debug(f"Could not get IP for interface {iface}: {e}")

            # Also try common interface names
            for common in ["eth0", "wlan0", "en0", "enp0s3", "wlp2s0"]:
                if common not in [i["name"] for i in interfaces]:
                    try:
                        ip = get_if_addr(common)
                        if ip and ip != "0.0.0.0":
                            interfaces.append({
                                "name": common,
                                "ip": ip,
                                "description": f"{common} ({ip})"
                            })
                    except:
                        pass

        except Exception as e:
            print(f"Error getting interfaces: {e}")

        if not interfaces:
            interfaces.append({
                "name": "any",
                "ip": "0.0.0.0",
                "description": "All interfaces"
            })

        return interfaces

    def _generate_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
        """Generate unique flow identifier."""
        # Sort to make bidirectional flows have same ID
        if (src_ip, src_port) > (dst_ip, dst_port):
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"

    def _process_packet(self, packet):
        """Process a captured packet and update flow statistics."""
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_len = len(packet)

        # Determine protocol and ports
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload_len = len(packet[TCP].payload) if packet[TCP].payload else 0
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload_len = len(packet[UDP].payload) if packet[UDP].payload else 0
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            src_port = 0
            dst_port = 0
            payload_len = len(packet[ICMP].payload) if packet[ICMP].payload else 0
        else:
            proto = "OTHER"
            src_port = 0
            dst_port = 0
            payload_len = 0

        self.packets_captured += 1
        current_time = time.time()

        # Generate flow ID
        flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto)

        # Get or create flow
        if flow_id not in self.flows:
            self.flows[flow_id] = NetworkFlow(
                flow_id=flow_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_time=current_time
            )

        flow = self.flows[flow_id]
        flow.last_time = current_time

        # Determine direction and update counters
        is_originator = (src_ip == flow.src_ip and src_port == flow.src_port)

        if is_originator:
            flow.orig_pkts += 1
            flow.orig_bytes += payload_len
            flow.orig_ip_bytes += ip_len
        else:
            flow.resp_pkts += 1
            flow.resp_bytes += payload_len
            flow.resp_ip_bytes += ip_len

        # Trigger callback for real-time updates (every 10 packets or significant flows)
        if self.on_flow_callback and (self.packets_captured % 10 == 0 or flow.orig_pkts + flow.resp_pkts >= 5):
            try:
                self.on_flow_callback(flow)
            except Exception as e:
                print(f"Flow callback error: {e}")

    def _capture_loop(self):
        """Main packet capture loop running in separate thread."""
        if not SCAPY_AVAILABLE:
            print("Scapy not available, running in demo mode")
            self._demo_capture_loop()
            return

        # Build BPF filter with validated IP
        bpf_filter = "ip"  # Only IP packets
        if self.target_filter:
            # Validate IP to prevent BPF filter injection
            validated_ip = validate_ip_filter(self.target_filter)
            bpf_filter = f"ip and host {validated_ip}"

        try:
            print(f"Starting capture on {self.interface} with filter: {bpf_filter}")

            # Use timeout-based capture to allow stopping
            while not self._stop_event.is_set():
                elapsed = time.time() - self.start_time
                if elapsed >= self.duration:
                    break

                # Capture in small batches
                try:
                    sniff(
                        iface=self.interface if self.interface != "any" else None,
                        filter=bpf_filter,
                        prn=self._process_packet,
                        store=False,
                        timeout=1,  # 1 second timeout for checking stop condition
                        stop_filter=lambda p: self._stop_event.is_set()
                    )
                except PermissionError:
                    print("ERROR: Permission denied. Run with sudo for packet capture.")
                    break
                except Exception as e:
                    if "Operation not permitted" in str(e):
                        print("ERROR: Need root privileges for packet capture. Run with: sudo python ...")
                    else:
                        print(f"Capture error: {e}")
                    break

        except Exception as e:
            print(f"Capture loop error: {e}")
        finally:
            self.is_capturing = False
            print(f"Capture stopped. Total packets: {self.packets_captured}, Flows: {len(self.flows)}")

    def _demo_capture_loop(self):
        """Demo capture loop when scapy is not available or no permissions."""
        import random

        print("Running in DEMO mode - generating simulated traffic")

        demo_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.1", "10.0.0.50", "8.8.8.8", "1.1.1.1"
        ]
        demo_ports = [22, 80, 443, 3389, 8080, 53, 445]

        while not self._stop_event.is_set():
            elapsed = time.time() - self.start_time
            if elapsed >= self.duration:
                break

            # Generate random flow
            src_ip = random.choice(demo_ips[:3])  # Local IPs
            dst_ip = random.choice(demo_ips)
            src_port = random.randint(40000, 65000)
            dst_port = random.choice(demo_ports)
            proto = random.choice(["TCP", "UDP"])

            flow_id = self._generate_flow_id(src_ip, dst_ip, src_port, dst_port, proto)

            if flow_id not in self.flows:
                self.flows[flow_id] = NetworkFlow(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    start_time=time.time()
                )

            flow = self.flows[flow_id]
            flow.last_time = time.time()
            flow.orig_pkts += random.randint(1, 10)
            flow.orig_bytes += random.randint(100, 5000)
            flow.orig_ip_bytes += random.randint(140, 5500)
            flow.resp_pkts += random.randint(0, 5)
            flow.resp_bytes += random.randint(0, 3000)
            flow.resp_ip_bytes += random.randint(0, 3500)

            self.packets_captured += flow.orig_pkts + flow.resp_pkts

            if self.on_flow_callback:
                try:
                    self.on_flow_callback(flow)
                except Exception as e:
                    print(f"Flow callback error: {e}")

            time.sleep(0.5)  # Simulate packet rate

        self.is_capturing = False
        print(f"Demo capture stopped. Simulated packets: {self.packets_captured}, Flows: {len(self.flows)}")

    def start_capture(
        self,
        interface: str,
        duration: int = 60,
        target_ip: Optional[str] = None,
        on_flow: Optional[Callable] = None,
        on_alert: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Start packet capture on specified interface.

        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            duration: Capture duration in seconds
            target_ip: Optional IP to filter (capture only traffic to/from this IP)
            on_flow: Callback function called for each flow update
            on_alert: Callback function called when alert is generated

        Returns:
            Status dictionary
        """
        if self.is_capturing:
            return {"status": "error", "message": "Capture already in progress"}

        self.interface = interface
        self.duration = duration
        self.target_filter = target_ip or ""
        self.on_flow_callback = on_flow
        self.on_alert_callback = on_alert
        self.flows = {}
        self.packets_captured = 0
        self.start_time = time.time()
        self.is_capturing = True
        self._stop_event.clear()

        # Start capture in background thread
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

        return {
            "status": "started",
            "interface": interface,
            "duration": duration,
            "target_ip": target_ip,
            "start_time": datetime.now().isoformat()
        }

    def stop_capture(self) -> Dict[str, Any]:
        """Stop active packet capture."""
        if not self.is_capturing:
            return {"status": "error", "message": "No capture in progress"}

        self._stop_event.set()

        if self.capture_thread:
            self.capture_thread.join(timeout=3)

        self.is_capturing = False

        return {
            "status": "stopped",
            "packets_captured": self.packets_captured,
            "flows_detected": len(self.flows),
            "duration_actual": time.time() - self.start_time if self.start_time else 0
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current capture status."""
        elapsed = time.time() - self.start_time if self.start_time else 0
        remaining = max(0, self.duration - elapsed) if self.is_capturing else 0

        return {
            "is_capturing": self.is_capturing,
            "interface": self.interface,
            "target_ip": self.target_filter,
            "duration": self.duration,
            "elapsed": round(elapsed, 1),
            "remaining": round(remaining, 1),
            "packets_captured": self.packets_captured,
            "flows_detected": len(self.flows),
            "start_time": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None
        }

    def get_flows(self) -> List[Dict]:
        """Get all captured flows as list of dictionaries."""
        return [flow.to_dict() for flow in self.flows.values()]

    def get_completed_flows(self, timeout: float = None) -> List[Dict]:
        """Get flows that appear to be complete (no activity for timeout seconds)."""
        timeout = timeout or self._flow_timeout
        current_time = time.time()

        completed = []
        for flow in self.flows.values():
            if current_time - flow.last_time > timeout:
                completed.append(flow.to_dict())

        return completed


# Global capture service instance
capture_service = NetworkCaptureService()
