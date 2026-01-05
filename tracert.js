const raw = require('raw-socket');
const dns = require('dns').promises;
const http = require('http');

const args = process.argv.slice(2);
if (!args[0]) {
    console.error("\x1b[31mError: No destination provided.\x1b[0m");
    console.log("Usage: node tracert.js <destination> [max_hops] [timeout]");
    process.exit(1);
}

const DESTINATION = args[0];
const MAX_HOPS = parseInt(args[1]) || 30;
const TIMEOUT = parseInt(args[2]) || 1000;

async function trace() {
    let targetIp;
    try {
        const lookup = await dns.lookup(DESTINATION);
        targetIp = lookup.address;
    } catch (e) {
        try {
            console.log(`Standard resolution failed. Checking for Minecraft SRV records...`);
            const srvRecords = await dns.resolveSrv(`_minecraft._tcp.${DESTINATION}`);
        
            if (srvRecords && srvRecords.length > 0) {
                const lookupSrv = await dns.lookup(srvRecords[0].name);
                targetIp = lookupSrv.address;
                console.log(`\x1b[32mSRV Found:\x1b[0m Redirecting to ${srvRecords[0].name} (${targetIp})`);
            } else throw new Error();
        } catch (e) {
            console.error("Could not resolve host.");
            process.exit(1);
        }
    }

    console.log(`Traceroute to ${DESTINATION} (${targetIp})...\n`);

    const probes = [];
    for (let i = 1; i <= MAX_HOPS; i++) {
        probes.push(sendIcmpProbe(targetIp, i));
    }

    const results = await Promise.all(probes);

    for (const res of results) {
        const hop = res.ttl.toString().padEnd(3);
        if (res.timeout) {
            console.log(`${hop} * * *`);
        } else {
            const location = await getLocation(res.ip);
            const ipPart = res.ip.padEnd(15);
            const timePart = `${res.time}ms`.padEnd(8);
            console.log(`${hop} ${ipPart}  ${timePart}  ${location}`);
        }
        if (res.reached) break;
    }
    process.exit(0);
}

function sendIcmpProbe(targetIp, ttl) {
    return new Promise((resolve) => {
        const socket = raw.createSocket({ protocol: raw.Protocol.ICMP });
        const start = Date.now();
        const id = (process.pid ^ ttl) & 0xFFFF;
        let finished = false;

        const buffer = Buffer.alloc(12);
        buffer.writeUInt8(8, 0); buffer.writeUInt8(0, 1);
        buffer.writeUInt16BE(0, 2); buffer.writeUInt16BE(id, 4);
        buffer.writeUInt16BE(ttl, 6); buffer.writeUInt16BE(checksum(buffer), 2);

        const finalize = (result) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            try { socket.close(); } catch (e) {}
            resolve(result);
        };

        const timer = setTimeout(() => finalize({ ttl, timeout: true }), TIMEOUT);

        socket.on("message", (buffer, source) => {
            const type = buffer[20];
            let receivedId = (type === 0) ? buffer.readUInt16BE(24) : buffer.readUInt16BE(52);
            if (receivedId === id) {
                finalize({ ttl, ip: source, time: Date.now() - start, reached: (type === 0 || source === targetIp) });
            }
        });

        socket.setOption(raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_TTL, ttl);
        socket.send(buffer, 0, buffer.length, targetIp, (err) => {
            if (err) finalize({ ttl, timeout: true });
        });
    });
}

function checksum(buffer) {
    let sum = 0;
    for (let i = 0; i < buffer.length; i += 2) sum += buffer.readUInt16BE(i);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (~sum & 0xFFFF);
}

function getLocation(ip) {
    return new Promise((resolve) => {
        http.get(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city`, (res) => {
            let data = '';
            res.on('data', d => data += d);
            res.on('end', () => {
                try {
                    const j = JSON.parse(data);
                    if (j.status === 'success') {
                        const parts = [j.country, j.regionName, j.city].filter(p => p && p.trim() !== "");
                        resolve(parts.join(', '));
                    } else {
                        resolve("No Data (Probably Local IP)");
                    }
                } catch (e) { resolve(""); }
            });
        }).on('error', () => resolve(""));
    });
}

trace();