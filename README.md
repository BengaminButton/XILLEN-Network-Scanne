# XILLEN Network Scanner

Advanced network reconnaissance and vulnerability scanner built with Node.js for comprehensive security assessments.

## 🚀 Features

- **Multi-threaded Port Scanning**: Fast concurrent port scanning with configurable thread count
- **Service Detection**: Automatic service identification and version detection
- **Vulnerability Assessment**: Built-in vulnerability checks for common services
- **Host Discovery**: Ping testing and hostname resolution
- **WHOIS Integration**: Domain registration information lookup
- **Banner Grabbing**: Service banner collection and analysis
- **Comprehensive Reporting**: JSON export with detailed scan results
- **Custom Port Ranges**: Flexible port specification and range scanning

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/xillen-network-scanner.git
cd xillen-network-scanner
npm install
```

## 📋 Prerequisites

- Node.js 14.0.0 or higher
- npm or yarn package manager
- Network access to target systems

## 🎯 Usage

### Basic Usage
```bash
node scanner.js 192.168.1.1
```

### Quick Scan
```bash
node scanner.js example.com --quick
```

### Custom Port Range
```bash
node scanner.js 192.168.1.1 --ports 1-1000
```

### Specific Ports
```bash
node scanner.js example.com --ports 80,443,8080,8443
```

### High Performance Scan
```bash
node scanner.js 192.168.1.1 --threads 200 --timeout 500
```

### Save Results
```bash
node scanner.js example.com --output results.json
```

## 📊 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports <ports>` | Port range or specific ports | Common ports |
| `-t, --timeout <ms>` | Connection timeout in milliseconds | 1000 |
| `-T, --threads <count>` | Number of concurrent threads | 100 |
| `-o, --output <file>` | Output file for results (JSON) | None |
| `--quick` | Quick scan (common ports only) | false |

## 🔍 Scan Types

### Port Scanning
- TCP connect scanning
- Service identification
- Banner grabbing
- Version detection

### Vulnerability Assessment
- SSH version vulnerabilities
- HTTP server vulnerabilities
- FTP security issues
- Common service misconfigurations

### Network Discovery
- Host availability (ping)
- DNS resolution
- WHOIS information
- Network topology analysis

## 📈 Performance Features

- **Concurrent Processing**: Multi-threaded scanning for maximum speed
- **Configurable Timeouts**: Adjustable connection timeouts
- **Memory Efficient**: Stream processing for large port ranges
- **Progress Indicators**: Real-time scan progress with spinners
- **Error Handling**: Graceful failure recovery

## 🛡️ Security Considerations

### Legal Notice
This tool is designed for authorized security testing only. Users must:

- Obtain proper authorization before scanning targets
- Comply with applicable laws and regulations
- Respect network policies and terms of service
- Use results responsibly and ethically

### Rate Limiting
The scanner includes built-in rate limiting to prevent network flooding:

- Configurable thread limits
- Connection timeouts
- Respectful scanning intervals

## 📋 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                XILLEN NETWORK SCANNER                      ║
║            Advanced Network Reconnaissance Tool            ║
╚══════════════════════════════════════════════════════════════╝

Target: example.com
Ports: 23 common ports
Threads: 100
Started: 1/15/2024, 2:30:25 PM

✓ Hostname resolved: 93.184.216.34
✓ Host is alive (45ms avg)
✓ Port scan completed: 3 open ports found
✓ Service detection completed for 3 services
✓ Vulnerability scan completed: 1 potential issues found
✓ WHOIS information retrieved

╔══════════════════════════════════════════════════════════════╗
║                        SCAN RESULTS                        ║
╚══════════════════════════════════════════════════════════════╝

Open Ports:
┌──────┬─────────┬────────┐
│ Port │ Service │ Status │
├──────┼─────────┼────────┤
│ 80   │ HTTP    │ Open   │
│ 443  │ HTTPS   │ Open   │
│ 8080 │ HTTP-Alt│ Open   │
└──────┴─────────┴────────┘

Vulnerabilities:
┌──────┬─────────┬──────────┬─────────────────┐
│ Port │ Service │ Severity │ CVE             │
├──────┼─────────┼──────────┼─────────────────┤
│ 80   │ HTTP    │ Info     │ N/A             │
└──────┴─────────┴──────────┴─────────────────┘

Scan completed successfully!
Open ports: 3
Services detected: 3
Vulnerabilities found: 1

Results saved to: scan_results.json
```

## 🔧 Configuration

### Environment Variables
```bash
export NODE_ENV=production
export SCANNER_TIMEOUT=2000
export SCANNER_THREADS=150
```

### Custom Port Lists
Create custom port lists by modifying the `getCommonPorts()` method or using command-line options.

## 📊 JSON Output Format

```json
{
  "target": "example.com",
  "timestamp": "2024-01-15T14:30:25.123Z",
  "hostInfo": {
    "hostname": "example.com",
    "addresses": ["93.184.216.34"],
    "family": 4
  },
  "openPorts": [
    {
      "port": 80,
      "status": "open",
      "service": "HTTP"
    }
  ],
  "services": [
    {
      "port": 80,
      "service": "HTTP",
      "version": "Apache/2.4.41",
      "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41",
      "details": {}
    }
  ],
  "vulnerabilities": [
    {
      "port": 80,
      "service": "HTTP",
      "cve": "N/A",
      "severity": "Info",
      "description": "HTTP service detected",
      "remediation": "Ensure HTTPS is enabled"
    }
  ],
  "networkInfo": {
    "ping": {
      "alive": true,
      "time": "45ms",
      "avg": "45"
    }
  }
}
```

## 🧪 Testing

```bash
npm test
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security assessments.

## 🔗 Related Projects

- [XILLEN OSINT Framework](../xillen-osint/) - Open source intelligence gathering
- [XILLEN Password Cracker](../xillen-password-cracker/) - Advanced password auditing
- [XILLEN Vulnerability Scanner](../xillen-vuln-scanner/) - Comprehensive vulnerability assessment
