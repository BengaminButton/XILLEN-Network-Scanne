#!/usr/bin/env node

const net = require('net');
const dns = require('dns');
const axios = require('axios');
const chalk = require('chalk');
const { Command } = require('commander');
const ora = require('ora');
const { table } = require('table');
const fs = require('fs-extra');
const ping = require('ping');

class XillenNetworkScanner {
    constructor(options = {}) {
        this.target = options.target;
        this.ports = options.ports || this.getCommonPorts();
        this.timeout = options.timeout || 1000;
        this.threads = options.threads || 100;
        this.output = options.output;
        this.results = {
            target: this.target,
            timestamp: new Date().toISOString(),
            hostInfo: {},
            openPorts: [],
            services: [],
            vulnerabilities: [],
            networkInfo: {}
        };
    }

    getCommonPorts() {
        return [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ];
    }

    banner() {
        const banner = `
${chalk.cyan('╔══════════════════════════════════════════════════════════════╗')}
${chalk.cyan('║                XILLEN NETWORK SCANNER                      ║')}
${chalk.cyan('║            Advanced Network Reconnaissance Tool            ║')}
${chalk.cyan('╚══════════════════════════════════════════════════════════════╝')}

${chalk.yellow('Target:')} ${this.target}
${chalk.yellow('Ports:')} ${this.ports.length} common ports
${chalk.yellow('Threads:')} ${this.threads}
${chalk.yellow('Started:')} ${new Date().toLocaleString()}
`;
        console.log(banner);
    }

    async resolveHostname() {
        const spinner = ora('Resolving hostname...').start();
        
        try {
            const addresses = await dns.promises.lookup(this.target, { all: true });
            this.results.hostInfo = {
                hostname: this.target,
                addresses: addresses.map(addr => addr.address),
                family: addresses[0].family
            };
            spinner.succeed(`Hostname resolved: ${addresses[0].address}`);
        } catch (error) {
            spinner.fail(`Failed to resolve hostname: ${error.message}`);
            this.results.hostInfo = {
                hostname: this.target,
                addresses: [this.target],
                family: net.isIP(this.target) === 4 ? 4 : 6
            };
        }
    }

    async pingHost() {
        const spinner = ora('Pinging target...').start();
        
        try {
            const result = await ping.promise.probe(this.target, {
                timeout: 3,
                extra: ['-c', '3']
            });
            
            this.results.networkInfo.ping = {
                alive: result.alive,
                time: result.time,
                min: result.min,
                max: result.max,
                avg: result.avg
            };
            
            if (result.alive) {
                spinner.succeed(`Host is alive (${result.avg}ms avg)`);
            } else {
                spinner.fail('Host is not responding to ping');
            }
        } catch (error) {
            spinner.fail(`Ping failed: ${error.message}`);
        }
    }

    async scanPort(port) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            const timeout = setTimeout(() => {
                socket.destroy();
                resolve({ port, status: 'closed', service: null });
            }, this.timeout);

            socket.connect(port, this.target, () => {
                clearTimeout(timeout);
                socket.destroy();
                resolve({ port, status: 'open', service: this.getServiceName(port) });
            });

            socket.on('error', () => {
                clearTimeout(timeout);
                resolve({ port, status: 'closed', service: null });
            });
        });
    }

    getServiceName(port) {
        const services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch', 27017: 'MongoDB'
        };
        return services[port] || 'Unknown';
    }

    async scanPorts() {
        const spinner = ora(`Scanning ${this.ports.length} ports...`).start();
        const openPorts = [];
        const batches = this.chunkArray(this.ports, this.threads);

        for (const batch of batches) {
            const promises = batch.map(port => this.scanPort(port));
            const results = await Promise.all(promises);
            
            for (const result of results) {
                if (result.status === 'open') {
                    openPorts.push(result);
                    this.results.openPorts.push(result);
                    spinner.text = `Found ${openPorts.length} open ports...`;
                }
            }
        }

        spinner.succeed(`Port scan completed: ${openPorts.length} open ports found`);
        return openPorts;
    }

    chunkArray(array, chunkSize) {
        const chunks = [];
        for (let i = 0; i < array.length; i += chunkSize) {
            chunks.push(array.slice(i, i + chunkSize));
        }
        return chunks;
    }

    async serviceDetection() {
        const spinner = ora('Detecting services...').start();
        
        for (const portInfo of this.results.openPorts) {
            try {
                const service = await this.detectService(portInfo.port);
                this.results.services.push({
                    port: portInfo.port,
                    service: portInfo.service,
                    version: service.version,
                    banner: service.banner,
                    details: service.details
                });
            } catch (error) {
                this.results.services.push({
                    port: portInfo.port,
                    service: portInfo.service,
                    version: 'Unknown',
                    banner: null,
                    details: null
                });
            }
        }
        
        spinner.succeed(`Service detection completed for ${this.results.services.length} services`);
    }

    async detectService(port) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            let banner = '';
            
            socket.setTimeout(3000);
            
            socket.connect(port, this.target, () => {
                socket.write('\r\n');
            });
            
            socket.on('data', (data) => {
                banner += data.toString();
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve(this.parseBanner(banner, port));
            });
            
            socket.on('error', () => {
                resolve({ version: 'Unknown', banner: null, details: null });
            });
        });
    }

    parseBanner(banner, port) {
        const details = {
            version: 'Unknown',
            banner: banner.trim(),
            details: {}
        };

        if (banner.includes('SSH')) {
            const versionMatch = banner.match(/SSH-(\d+\.\d+)/);
            if (versionMatch) {
                details.version = `SSH ${versionMatch[1]}`;
            }
        } else if (banner.includes('HTTP')) {
            const versionMatch = banner.match(/Server: ([^\r\n]+)/i);
            if (versionMatch) {
                details.version = versionMatch[1];
            }
        } else if (banner.includes('FTP')) {
            const versionMatch = banner.match(/220 ([^\r\n]+)/);
            if (versionMatch) {
                details.version = versionMatch[1];
            }
        }

        return details;
    }

    async vulnerabilityScan() {
        const spinner = ora('Scanning for vulnerabilities...').start();
        
        for (const service of this.results.services) {
            const vulns = await this.checkVulnerabilities(service);
            this.results.vulnerabilities.push(...vulns);
        }
        
        spinner.succeed(`Vulnerability scan completed: ${this.results.vulnerabilities.length} potential issues found`);
    }

    async checkVulnerabilities(service) {
        const vulnerabilities = [];
        
        if (service.service === 'SSH' && service.version.includes('OpenSSH')) {
            const version = service.version.match(/(\d+\.\d+)/);
            if (version && parseFloat(version[1]) < 7.4) {
                vulnerabilities.push({
                    port: service.port,
                    service: service.service,
                    cve: 'CVE-2018-15473',
                    severity: 'Medium',
                    description: 'OpenSSH username enumeration vulnerability',
                    remediation: 'Update OpenSSH to version 7.4 or later'
                });
            }
        }
        
        if (service.service === 'HTTP' && service.version.includes('Apache')) {
            const version = service.version.match(/(\d+\.\d+\.\d+)/);
            if (version && parseFloat(version[1]) < 2.4) {
                vulnerabilities.push({
                    port: service.port,
                    service: service.service,
                    cve: 'CVE-2017-15715',
                    severity: 'High',
                    description: 'Apache HTTP Server vulnerability',
                    remediation: 'Update Apache to version 2.4.29 or later'
                });
            }
        }
        
        if (service.service === 'FTP') {
            vulnerabilities.push({
                port: service.port,
                service: service.service,
                cve: 'N/A',
                severity: 'Info',
                description: 'FTP service detected - consider using SFTP',
                remediation: 'Disable FTP and use SFTP or FTPS'
            });
        }
        
        return vulnerabilities;
    }

    async whoisLookup() {
        const spinner = ora('Performing WHOIS lookup...').start();
        
        try {
            const response = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${this.target}`, {
                timeout: 10000
            });
            
            this.results.networkInfo.whois = response.data;
            spinner.succeed('WHOIS information retrieved');
        } catch (error) {
            spinner.fail(`WHOIS lookup failed: ${error.message}`);
        }
    }

    displayResults() {
        console.log(chalk.cyan('\n╔══════════════════════════════════════════════════════════════╗'));
        console.log(chalk.cyan('║                        SCAN RESULTS                        ║'));
        console.log(chalk.cyan('╚══════════════════════════════════════════════════════════════╝\n'));

        if (this.results.openPorts.length > 0) {
            const portData = [
                [chalk.yellow('Port'), chalk.yellow('Service'), chalk.yellow('Status')]
            ];
            
            this.results.openPorts.forEach(port => {
                portData.push([
                    port.port.toString(),
                    port.service || 'Unknown',
                    chalk.green('Open')
                ]);
            });
            
            console.log(chalk.blue('Open Ports:'));
            console.log(table(portData));
        }

        if (this.results.vulnerabilities.length > 0) {
            const vulnData = [
                [chalk.yellow('Port'), chalk.yellow('Service'), chalk.yellow('Severity'), chalk.yellow('CVE')]
            ];
            
            this.results.vulnerabilities.forEach(vuln => {
                const severityColor = vuln.severity === 'High' ? chalk.red : 
                                    vuln.severity === 'Medium' ? chalk.yellow : chalk.blue;
                vulnData.push([
                    vuln.port.toString(),
                    vuln.service,
                    severityColor(vuln.severity),
                    vuln.cve
                ]);
            });
            
            console.log(chalk.red('\nVulnerabilities:'));
            console.log(table(vulnData));
        }

        console.log(chalk.green(`\nScan completed successfully!`));
        console.log(chalk.yellow(`Open ports: ${this.results.openPorts.length}`));
        console.log(chalk.yellow(`Services detected: ${this.results.services.length}`));
        console.log(chalk.yellow(`Vulnerabilities found: ${this.results.vulnerabilities.length}`));
    }

    async saveResults() {
        if (this.output) {
            await fs.writeJson(this.output, this.results, { spaces: 2 });
            console.log(chalk.green(`\nResults saved to: ${this.output}`));
        }
    }

    async run() {
        this.banner();
        
        try {
            await this.resolveHostname();
            await this.pingHost();
            await this.scanPorts();
            await this.serviceDetection();
            await this.vulnerabilityScan();
            await this.whoisLookup();
            
            this.displayResults();
            await this.saveResults();
            
        } catch (error) {
            console.error(chalk.red(`\nScan failed: ${error.message}`));
            process.exit(1);
        }
    }
}

const program = new Command();

program
    .name('xillen-network-scanner')
    .description('Advanced network reconnaissance and vulnerability scanner')
    .version('1.0.0');

program
    .argument('<target>', 'Target IP address or hostname')
    .option('-p, --ports <ports>', 'Port range or specific ports (e.g., 1-1000 or 80,443,8080)')
    .option('-t, --timeout <ms>', 'Connection timeout in milliseconds', '1000')
    .option('-T, --threads <count>', 'Number of concurrent threads', '100')
    .option('-o, --output <file>', 'Output file for results (JSON format)')
    .option('--quick', 'Quick scan (common ports only)')
    .action(async (target, options) => {
        let ports;
        
        if (options.quick) {
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443];
        } else if (options.ports) {
            if (options.ports.includes('-')) {
                const [start, end] = options.ports.split('-').map(Number);
                ports = Array.from({ length: end - start + 1 }, (_, i) => start + i);
            } else {
                ports = options.ports.split(',').map(Number);
            }
        }
        
        const scanner = new XillenNetworkScanner({
            target,
            ports,
            timeout: parseInt(options.timeout),
            threads: parseInt(options.threads),
            output: options.output
        });
        
        await scanner.run();
    });

program.parse();
