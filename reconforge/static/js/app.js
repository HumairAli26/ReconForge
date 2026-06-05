// app.js
// ------
// Handles frontend application logic, API calls, and UI event binding.

const API_BASE = "http://localhost:5000/api";

// Elements
const targetSubnetInput = document.getElementById("target-subnet");
const btnDetect = document.getElementById("btn-detect");
const btnScanNetwork = document.getElementById("btn-scan-network");
const btnExploit = document.getElementById("btn-exploit");
const btnScanPorts = document.getElementById("btn-scan-ports");
const exploitSelect = document.getElementById("exploit-select");
const msfStatusBadge = document.getElementById("msf-status");
const consoleOutput = document.getElementById("console-output");
const btnClearConsole = document.getElementById("btn-clear-console");

// Card Elements
const hostDetailsCard = document.getElementById("host-details-card");
const hostIp = document.getElementById("host-ip");
const hostMac = document.getElementById("host-mac");
const hostHostname = document.getElementById("host-hostname");
const hostVendor = document.getElementById("host-vendor");
const hostType = document.getElementById("host-type");
const hostRisk = document.getElementById("host-risk");
const portsList = document.getElementById("ports-list");

let currentDevices = [];
let selectedDeviceData = null;

// Initial checks
document.addEventListener("DOMContentLoaded", () => {
    checkMsfAvailability();
    loadMsfModules();
    detectSubnet();
});

// Auto-detect Subnet
btnDetect.addEventListener("click", detectSubnet);

function detectSubnet() {
    fetch(`${API_BASE}/network/detect`)
        .then(res => res.json())
        .then(data => {
            targetSubnetInput.value = data.network;
            logConsole(`[+] Auto-detected network: ${data.network}`);
        })
        .catch(err => {
            logConsole(`[-] Failed to detect network: ${err.message}`);
        });
}

// MSF Availability
function checkMsfAvailability() {
    fetch(`${API_BASE}/msf/available`)
        .then(res => res.json())
        .then(data => {
            if (data.available) {
                msfStatusBadge.textContent = "ONLINE";
                msfStatusBadge.className = "status-badge badge-success";
                logConsole("[+] Metasploit integration engine is ONLINE.");
            } else {
                msfStatusBadge.textContent = "OFFLINE";
                msfStatusBadge.className = "status-badge badge-danger";
                logConsole("[-] Metasploit is offline. Using fallback python scanner.");
            }
        });
}

// Load Modules
function loadMsfModules() {
    fetch(`${API_BASE}/msf/modules`)
        .then(res => res.json())
        .then(data => {
            exploitSelect.innerHTML = '<option value="">Select exploit...</option>';
            data.modules.forEach(mod => {
                const opt = document.createElement("option");
                opt.value = mod.key;
                opt.textContent = `${mod.category} - ${mod.key}`;
                exploitSelect.appendChild(opt);
            });
        });
}

// Subnet Discovery Scan
btnScanNetwork.addEventListener("click", () => {
    const net = targetSubnetInput.value;
    logConsole(`[*] Starting ARP subnet scan on: ${net}...`);
    btnScanNetwork.disabled = true;
    btnScanNetwork.textContent = "Scanning Subnet...";

    fetch(`${API_BASE}/scan/network`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ network: net })
    })
    .then(res => res.json())
    .then(data => {
        btnScanNetwork.disabled = false;
        btnScanNetwork.textContent = "Discover Hosts";
        if (data.success) {
            currentDevices = data.devices;
            logConsole(`[+] Subnet scan complete. Found ${currentDevices.length} hosts.`);
            updateNetworkTopology(currentDevices);
            document.getElementById("stat-devices").textContent = currentDevices.length;
        } else {
            logConsole("[-] Subnet scan failed.");
        }
    })
    .catch(err => {
        btnScanNetwork.disabled = false;
        btnScanNetwork.textContent = "Discover Hosts";
        logConsole(`[-] Scan Error: ${err.message}`);
    });
});

// Raycasting Callback (from network3d.js)
window.showHostDetails = function(deviceData) {
    if (deviceData.ip === "Gateway") {
        hostDetailsCard.classList.add("hidden");
        selectedDeviceData = null;
        btnExploit.disabled = true;
        return;
    }

    selectedDeviceData = deviceData;
    hostDetailsCard.classList.remove("hidden");

    hostIp.textContent = deviceData.ip;
    hostMac.textContent = deviceData.mac;
    hostHostname.textContent = deviceData.hostname || "Unknown";
    hostVendor.textContent = deviceData.vendor || "Unknown";
    hostType.textContent = deviceData.device_type || "Unknown";
    hostRisk.textContent = deviceData.risk || "Clean";

    // Set styling for risk badge
    if (deviceData.risk === "Exploited" || deviceData.exploited) {
        hostRisk.className = "badge badge-danger";
    } else if (deviceData.risk === "Vulnerable" || (deviceData.vulns && deviceData.vulns.length > 0)) {
        hostRisk.className = "badge badge-warn";
    } else {
        hostRisk.className = "badge badge-success";
    }

    // Populate ports list
    portsList.innerHTML = "";
    if (deviceData.open_ports && deviceData.open_ports.length > 0) {
        deviceData.open_ports.forEach(port => {
            const li = document.createElement("li");
            const svc = deviceData.services[port]?.service || "unknown";
            li.textContent = `Port ${port}: ${svc}`;
            portsList.appendChild(li);
        });
    } else {
        portsList.innerHTML = "<li>No open ports scanned yet.</li>";
    }

    btnExploit.disabled = false;
};

// Port Scan Event
btnScanPorts.addEventListener("click", () => {
    if (!selectedDeviceData) return;
    const ip = selectedDeviceData.ip;
    logConsole(`[*] Starting port/service scan on host: ${ip}...`);
    btnScanPorts.disabled = true;
    btnScanPorts.textContent = "Scanning Ports...";

    fetch(`${API_BASE}/scan/ports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        btnScanPorts.disabled = false;
        btnScanPorts.textContent = "Scan Ports & Services";
        if (data.success) {
            logConsole(`[+] Service scan complete for ${ip}.`);
            // Update device object in list and refresh details view
            const idx = currentDevices.findIndex(d => d.ip === ip);
            if (idx !== -1) {
                currentDevices[idx] = data.device;
            }
            window.showHostDetails(data.device);
            updateNetworkTopology(currentDevices);

            // Update stats count
            const vulnDevices = currentDevices.filter(d => d.vulns && d.vulns.length > 0).length;
            document.getElementById("stat-vulns").textContent = vulnDevices;
        } else {
            logConsole(`[-] Port scan failed for ${ip}.`);
        }
    })
    .catch(err => {
        btnScanPorts.disabled = false;
        btnScanPorts.textContent = "Scan Ports & Services";
        logConsole(`[-] Port Scan Error: ${err.message}`);
    });
});

// Metasploit Exploit Run
btnExploit.addEventListener("click", () => {
    if (!selectedDeviceData || !exploitSelect.value) {
        logConsole("[-] Select both a target device and a Metasploit exploit module first.");
        return;
    }
    const ip = selectedDeviceData.ip;
    const mod = exploitSelect.value;

    logConsole(`[*] Triggering Metasploit exploit module: '${mod}' against ${ip}...`);
    btnExploit.disabled = true;
    btnExploit.textContent = "Exploiting Target...";

    fetch(`${API_BASE}/msf/exploit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip, module: mod })
    })
    .then(res => res.json())
    .then(data => {
        btnExploit.disabled = false;
        btnExploit.textContent = "Run Assessment Exploit";
        if (data.success) {
            logConsole(`[+] Exploit completed successfully against ${ip}! Check output log.`);
            logConsole(data.output);

            // Update device state
            const idx = currentDevices.findIndex(d => d.ip === ip);
            if (idx !== -1) {
                currentDevices[idx].exploited = true;
                currentDevices[idx].risk = "Exploited";
            }
            window.showHostDetails(currentDevices[idx]);
            updateNetworkTopology(currentDevices);
        } else {
            logConsole(`[-] Exploit run failed: ${data.error}`);
            if (data.output) logConsole(data.output);
        }
    })
    .catch(err => {
        btnExploit.disabled = false;
        btnExploit.textContent = "Run Assessment Exploit";
        logConsole(`[-] Exploit connection failed: ${err.message}`);
    });
});

// Close card
document.querySelector(".close-btn").addEventListener("click", () => {
    hostDetailsCard.classList.add("hidden");
    selectedDeviceData = null;
    btnExploit.disabled = true;
});

// Clear console log
btnClearConsole.addEventListener("click", () => {
    consoleOutput.innerHTML = "";
});

// Helper for console logging
function logConsole(message) {
    consoleOutput.innerHTML += `\n${message}`;
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}
