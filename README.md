# Packet Sniffer & Network Anomaly Detector

A comprehensive Windows-based Python tool for capturing, analyzing, and detecting anomalies in network traffic.

## Features

### Phase 1: Packet Sniffer (MVP)
- ✅ Real-time packet capture on Windows (requires npcap)
- ✅ Multi-protocol support (TCP, UDP, DNS, HTTP, ICMP, ARP)
- ✅ Flow-based aggregation and statistics
- ✅ Multiple export formats (CSV, JSON)
- ✅ Protocol filtering and packet inspection
- ✅ SQLite-based persistent storage

### Phase 2: Anomaly Detection
- 🔄 Behavioral baseline learning
- 🔄 Statistical anomaly detection (Z-score analysis)
- 🔄 Port scanning detection
- 🔄 DNS exfiltration detection
- 🔄 Machine learning-based outlier detection (Isolation Forest)
- 🔄 Real-time alerting with configurable thresholds

## Quick Start

### Prerequisites
- Windows 10+
- Python 3.8+
- Administrator privileges (for packet capture)

### Installation

1. **Install npcap (Windows packet capture library)**
   ```bash
   # Download and install from: https://nmap.org/npcap/
   # Or use winget:
   winget install Nmap.npcap
   ```

2. **Clone and setup the project**
   ```bash
   cd packet-sniffer
   pip install -r requirements.txt
   ```

### Basic Usage

```bash
# List available network interfaces
python src/main.py list-interfaces

# Start capturing packets (default filter: all traffic)
python src/main.py capture --interface 1 --duration 60

# Analyze captured data
python src/main.py analyze

# Export to CSV
python src/main.py export --format csv

# Run anomaly detection
python src/main.py detect-anomaly --sensitivity high

# Real-time monitoring
python src/main.py monitor
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation, including:
- System components and responsibilities
- Data flow diagrams
- Technology stack rationale
- Design patterns and decisions

## Roadmap

See [PROJECT_ROADMAP.md](PROJECT_ROADMAP.md) for phased development timeline and milestones.

## Project Structure

```
packet-sniffer/
├── src/                    # Source code
│   ├── main.py            # CLI entry point
│   ├── capture.py         # Packet capture module
│   ├── processing.py      # Packet parsing & aggregation
│   ├── storage.py         # Database layer
│   ├── analysis.py        # Traffic analysis
│   ├── anomaly.py         # Anomaly detection (Phase 2)
│   ├── export.py          # Export functionality
│   └── utils/             # Utility modules
├── config/                # Configuration files
├── tests/                 # Unit and integration tests
├── docs/                  # Documentation
├── data/                  # Data storage & models
├── ARCHITECTURE.md        # Detailed architecture
├── PROJECT_ROADMAP.md     # Development timeline
└── requirements.txt       # Python dependencies
```

## Development Status

- **Phase 1:** In progress (Week 1-2)
  - [ ] Core capture module
  - [ ] Processing pipeline
  - [ ] Storage layer
  - [ ] Basic CLI

- **Phase 2:** Planned (Week 3-4)
  - [ ] Anomaly detection engine
  - [ ] Alerting system

- **Phase 3:** Planned (Week 5)
  - [ ] Testing & documentation
  - [ ] Performance optimization

## Documentation

- [Architecture](ARCHITECTURE.md) - System design and components
- [Roadmap](PROJECT_ROADMAP.md) - Development timeline
- [Installation Guide](docs/INSTALLATION.md) - Setup instructions
- [Usage Guide](docs/USAGE.md) - Command reference
- [API Reference](docs/API_REFERENCE.md) - Code API documentation

## Requirements

See [requirements.txt](requirements.txt) for dependencies:
- **Capture:** scapy
- **Processing:** pandas
- **Analysis:** scikit-learn, scipy, numpy
- **CLI:** click
- **Config:** pyyaml
- **Output:** rich

## Windows-Specific Notes

1. **Npcap Requirement:** Packet capture requires npcap (successor to WinPcap)
2. **Admin Rights:** Must run as administrator for packet capture
3. **Network Interface:** Tool enumerates available NICs; select appropriate one
4. **Firewall:** Consider Windows Firewall impact on traffic visibility

## Performance Targets

- Capture: 100+ packets/sec
- Processing: <10ms latency for flow aggregation
- Memory: <500MB for 10K packets
- Database queries: <100ms for historical data

## License

[Specify your license]

## Contributing

[Contribution guidelines]

## Contact

[Contact information]

---

**Note:** This tool is in active development. Phase 1 (Packet Sniffer MVP) is currently underway.
