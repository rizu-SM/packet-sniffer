"""Packet Sniffer & Network Anomaly Detector

A Windows-based Python tool for capturing network packets and detecting anomalous behavior.
"""

__version__ = "0.1.0"
__author__ = "Network Security Team"

from src.capture import PacketCapture, PacketInfo, list_interfaces

__all__ = [
    'PacketCapture',
    'PacketInfo',
    'list_interfaces',
]
