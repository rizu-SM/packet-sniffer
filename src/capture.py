"""
Packet Capture Module

Handles raw network packet capture on Windows using npcap and scapy.
Provides interface enumeration, filtering, and packet queue management.
"""

import logging
import threading
import queue
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import time

from scapy.all import sniff, conf, get_if_list, get_if_by_description, IP, IPv6
from scapy.layers.l2 import Ether

logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Container for captured packet metadata and raw packet."""
    timestamp: datetime
    packet: Any  # Scapy packet object
    interface: str
    packet_len: int
    
    def __repr__(self) -> str:
        return (
            f"PacketInfo(ts={self.timestamp.isoformat()}, "
            f"len={self.packet_len}, iface={self.interface})"
        )


class PacketCapture:
    """
    Manages live packet capture on Windows using npcap.
    
    Features:
    - Enumerate available network interfaces
    - Apply protocol/IP/port filters
    - Capture packets into a queue
    - Background thread-based sniffing
    - Graceful start/stop
    
    Example:
        >>> capture = PacketCapture()
        >>> capture.start(interface=0, duration=60)
        >>> packet = capture.get_packet(timeout=1)
        >>> capture.stop()
    """
    
    def __init__(self, packet_queue_size: int = 10000):
        """
        Initialize packet capture.
        
        Args:
            packet_queue_size: Maximum packets to buffer in queue
        """
        self.packet_queue: queue.Queue = queue.Queue(maxsize=packet_queue_size)
        self.is_sniffing = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.packets_captured = 0
        self.packets_dropped = 0
        self.start_time: Optional[datetime] = None
        
        # Filter settings
        self.filter_str: str = ""
        self.interface: str = ""
        
        # Check npcap availability
        self._check_npcap()
    
    @staticmethod
    def _check_npcap() -> None:
        """
        Verify npcap is installed and accessible.
        
        Raises:
            RuntimeError: If npcap is not available
        """
        try:
            # Try to get interface list - this requires npcap on Windows
            interfaces = get_if_list()
            if not interfaces:
                raise RuntimeError(
                    "No network interfaces found. "
                    "Ensure npcap is installed: https://nmap.org/npcap/"
                )
            logger.info(f"npcap detected with {len(interfaces)} interface(s)")
        except Exception as e:
            raise RuntimeError(
                f"Failed to access network interfaces. "
                f"Please install npcap from https://nmap.org/npcap/ "
                f"Error: {str(e)}"
            ) from e
    
    def get_interfaces(self) -> List[Dict[str, str]]:
        """
        Enumerate available network interfaces.
        
        Returns:
            List of dicts with 'id', 'name', 'description' keys
        """
        try:
            interfaces = []
            if_list = get_if_list()
            
            for idx, if_name in enumerate(if_list):
                try:
                    # Try to get more descriptive name
                    if_desc = get_if_by_description(if_name)
                    if_desc = if_desc or if_name
                except Exception:
                    if_desc = if_name
                
                interfaces.append({
                    'id': idx,
                    'name': if_name,
                    'description': str(if_desc)
                })
            
            return interfaces
        except Exception as e:
            logger.error(f"Failed to enumerate interfaces: {e}")
            return []
    
    def set_filter(
        self,
        protocols: Optional[List[str]] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        ports: Optional[List[int]] = None
    ) -> str:
        """
        Build and set a BPF (Berkeley Packet Filter) string.
        
        Args:
            protocols: List of protocols to capture (tcp, udp, dns, http, icmp, arp)
            src_ip: Source IP address or CIDR range
            dst_ip: Destination IP address or CIDR range
            ports: List of port numbers
        
        Returns:
            The constructed filter string
        """
        filters = []
        
        # Protocol filter
        if protocols:
            protocol_map = {
                'tcp': 'tcp',
                'udp': 'udp',
                'dns': 'udp port 53',
                'http': 'tcp port 80',
                'https': 'tcp port 443',
                'icmp': 'icmp',
                'arp': 'arp'
            }
            protocol_filters = [
                protocol_map.get(p, p) for p in protocols
            ]
            if protocol_filters:
                filters.append(f"({' or '.join(protocol_filters)})")
        
        # Source IP filter
        if src_ip:
            filters.append(f"src {src_ip}")
        
        # Destination IP filter
        if dst_ip:
            filters.append(f"dst {dst_ip}")
        
        # Port filter
        if ports:
            port_str = ' or '.join([str(p) for p in ports])
            filters.append(f"(port {port_str})")
        
        self.filter_str = ' and '.join(filters) if filters else ""
        logger.info(f"Filter set: '{self.filter_str or 'none'}'")
        return self.filter_str
    
    def _packet_callback(self, packet: Any) -> None:
        """
        Callback function for each captured packet.
        Called by scapy sniffer thread.
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = PacketInfo(
                timestamp=datetime.now(),
                packet=packet,
                interface=self.interface,
                packet_len=len(packet)
            )
            
            # Try to add to queue; drop if full
            try:
                self.packet_queue.put_nowait(packet_info)
                self.packets_captured += 1
            except queue.Full:
                self.packets_dropped += 1
                logger.warning("Packet queue full - dropping packet")
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start(
        self,
        interface: int = 0,
        duration: Optional[float] = None,
        packet_count: Optional[int] = None
    ) -> None:
        """
        Start packet capture in background thread.
        
        Args:
            interface: Interface ID (from get_interfaces) or name
            duration: Capture duration in seconds (None = infinite)
            packet_count: Stop after N packets (None = no limit)
        
        Raises:
            RuntimeError: If already sniffing or invalid interface
        """
        if self.is_sniffing:
            raise RuntimeError("Already sniffing - call stop() first")
        
        # Get interface name if ID provided
        if isinstance(interface, int):
            interfaces = self.get_interfaces()
            if interface >= len(interfaces):
                raise ValueError(
                    f"Invalid interface ID {interface}. "
                    f"Available: 0-{len(interfaces)-1}"
                )
            self.interface = interfaces[interface]['name']
        else:
            self.interface = interface
        
        self.is_sniffing = True
        self.start_time = datetime.now()
        self.packets_captured = 0
        self.packets_dropped = 0
        
        logger.info(
            f"Starting capture on interface '{self.interface}' "
            f"with filter: '{self.filter_str or 'none'}'"
        )
        
        # Start sniffing in background thread
        self.sniffer_thread = threading.Thread(
            target=self._sniff_worker,
            args=(duration, packet_count),
            daemon=True
        )
        self.sniffer_thread.start()
    
    def _sniff_worker(
        self,
        duration: Optional[float] = None,
        packet_count: Optional[int] = None
    ) -> None:
        """
        Worker thread that runs scapy sniffer.
        
        Args:
            duration: Capture duration in seconds
            packet_count: Stop after N packets
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=self.filter_str or None,
                timeout=duration,
                store=False,
                stop_filter=lambda x: not self.is_sniffing,
                # For Windows, promisc might not work as expected
                promisc=False
            )
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
        finally:
            self.is_sniffing = False
            logger.info("Packet capture stopped")
    
    def stop(self) -> None:
        """Stop packet capture and wait for thread to finish."""
        if not self.is_sniffing:
            logger.warning("Not currently sniffing")
            return
        
        logger.info("Stopping packet capture...")
        self.is_sniffing = False
        
        # Wait for thread with timeout
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
            if self.sniffer_thread.is_alive():
                logger.warning("Sniffer thread did not stop cleanly")
    
    def get_packet(self, timeout: float = 1.0) -> Optional[PacketInfo]:
        """
        Retrieve next packet from queue.
        
        Args:
            timeout: How long to wait for packet (seconds)
        
        Returns:
            PacketInfo object or None if timeout
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_packets_batch(
        self,
        count: int = 100,
        timeout: float = 1.0
    ) -> List[PacketInfo]:
        """
        Retrieve multiple packets at once.
        
        Args:
            count: Maximum packets to retrieve
            timeout: How long to wait (seconds)
        
        Returns:
            List of PacketInfo objects (may be fewer than requested)
        """
        packets = []
        deadline = time.time() + timeout
        
        while len(packets) < count:
            remaining = max(0.1, deadline - time.time())
            packet = self.get_packet(timeout=remaining)
            if packet:
                packets.append(packet)
            else:
                break
        
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get capture statistics.
        
        Returns:
            Dictionary with capture stats
        """
        elapsed = (
            (datetime.now() - self.start_time).total_seconds()
            if self.start_time else 0
        )
        
        return {
            'is_sniffing': self.is_sniffing,
            'interface': self.interface,
            'filter': self.filter_str or 'none',
            'packets_captured': self.packets_captured,
            'packets_dropped': self.packets_dropped,
            'queue_size': self.packet_queue.qsize(),
            'elapsed_seconds': elapsed,
            'packets_per_sec': (
                self.packets_captured / elapsed if elapsed > 0 else 0
            )
        }
    
    def flush_queue(self) -> List[PacketInfo]:
        """
        Get all remaining packets in queue.
        
        Returns:
            List of all PacketInfo objects in queue
        """
        packets = []
        while True:
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets


def list_interfaces() -> None:
    """CLI helper: Display available network interfaces."""
    try:
        capture = PacketCapture()
        interfaces = capture.get_interfaces()
        
        if not interfaces:
            print("No network interfaces found")
            return
        
        print("\nAvailable Network Interfaces:")
        print("-" * 80)
        for iface in interfaces:
            print(f"  [{iface['id']}] {iface['name']:<20} {iface['description']}")
        print("-" * 80)
    except RuntimeError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)
    list_interfaces()
