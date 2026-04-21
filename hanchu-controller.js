        // BLE Service and Characteristic UUIDs
        // Primary: ffff (confirmed on this device). Fallback: ff00 (other units).
        const SERVICE_UUID          = '0000ffff-0000-1000-8000-00805f9b34fb';
        const SERVICE_UUID_FALLBACK = '0000ff00-0000-1000-8000-00805f9b34fb';
        const READ_CHAR_UUID        = '0000ff01-0000-1000-8000-00805f9b34fb';
        const WRITE_CHAR_UUID       = '0000ff02-0000-1000-8000-00805f9b34fb';

        // AES constants — must match Swift AESHelper exactly
        const BASE_KEY = 'gxkj@2099@1914zy';
        const BASE_IV  = '9z64Qr8mZH7Pg8d1';

        // Global state
        let device = null;
        let readCharacteristic = null;
        let writeCharacteristic = null;
        let dynamicKey = null;
        let randomFix = null;
        let autoRefreshInterval = null;

        // Pending write confirmations: key → { resolve, reject, timeoutId }
        const pendingWrites = new Map();
        
        // Historical data storage
        let historicalData = {
            timestamps: [],
            soc: [],
            voltage: [],
            current: [],
            power: [],
            temperature: [],
            pvPower: [],
            gridPower: []
        };
        
        // Charts
        let batteryChart = null;
        let solarChart = null;
        let gridChart = null;
        let temperatureChart = null;

        // AES Encryption Helper — matches Swift AESHelper exactly (AES-128-CFB8)
        const AESHelper = {
            // Convert Uint8Array → CryptoJS WordArray (big-endian)
            _toWordArray(bytes) {
                const words = [];
                for (let i = 0; i < bytes.length; i += 4) {
                    words.push(
                        ((bytes[i]   || 0) << 24) |
                        ((bytes[i+1] || 0) << 16) |
                        ((bytes[i+2] || 0) <<  8) |
                        ((bytes[i+3] || 0))
                    );
                }
                return CryptoJS.lib.WordArray.create(words, bytes.length);
            },

            // Encrypt one 16-byte block with AES-128-ECB, return first 16 bytes
            // (matches Swift CCCrypt kCCEncrypt / kCCAlgorithmAES / kCCOptionECBMode)
            _ecbBlock(keyBytes, blockBytes) {
                const key = this._toWordArray(keyBytes);
                const blk = this._toWordArray(blockBytes);
                const enc = CryptoJS.AES.encrypt(blk, key, {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.Pkcs7   // input is 16 bytes; PKCS7 adds a padding block
                });
                // ECB encrypts blocks independently — first 16 bytes = encrypt(blockBytes)
                const w = enc.ciphertext.words;
                const out = new Uint8Array(16);
                for (let i = 0; i < 4; i++) {
                    out[i*4]   = (w[i] >>> 24) & 0xFF;
                    out[i*4+1] = (w[i] >>> 16) & 0xFF;
                    out[i*4+2] = (w[i] >>>  8) & 0xFF;
                    out[i*4+3] =  w[i]          & 0xFF;
                }
                return out;
            },

            // Generate dynamic key — matches Swift generateDynamicKey(randomFix:)
            // offset = ASCII(lastChar) % 10; replace BASE_KEY[offset..offset+5] with randomFix
            generateDynamicKey(fix) {
                if (fix.length !== 6) {
                    console.error('randomFix must be exactly 6 characters');
                    return BASE_KEY;
                }
                const offset = fix.charCodeAt(5) % 10;
                const keyArr = BASE_KEY.split('');
                for (let i = 0; i < 6; i++) {
                    if (offset + i < keyArr.length) keyArr[offset + i] = fix[i];
                }
                const dynKey = keyArr.join('');
                log(`🔑 Dynamic key generated (offset=${offset})`);
                return dynKey;
            },

            // Internal CFB8 core — isDecrypt controls feedback byte
            _cfb8(data, key) {
                const enc   = new TextEncoder();
                const keyB  = enc.encode(key).slice(0, 16);
                let   iv    = enc.encode(BASE_IV).slice(0, 16);
                const input = (data instanceof Uint8Array) ? data : new Uint8Array(data);
                const output = new Uint8Array(input.length);

                for (let i = 0; i < input.length; i++) {
                    const ks      = this._ecbBlock(keyB, iv);
                    const encByte = ks[0] ^ input[i];
                    output[i]     = encByte;
                    // CFB8 feedback: shift IV left 1 byte, append ciphertext byte
                    const newIv = new Uint8Array(16);
                    newIv.set(iv.subarray(1));
                    newIv[15] = encByte;
                    iv = newIv;
                }
                return output;
            },

            // Encrypt with current dynamic key (CFB8)
            encrypt(data) {
                if (!dynamicKey) { log('❌ No dynamic key!', 'error'); return null; }
                return this._cfb8(data, dynamicKey);
            },

            // Decrypt with current dynamic key (CFB8)
            // For CFB8, decrypt = encrypt the IV block then XOR, but feedback uses ciphertext byte
            decrypt(encryptedData) {
                if (!dynamicKey) { log('❌ No dynamic key!', 'error'); return null; }
                try {
                    const enc   = new TextEncoder();
                    const keyB  = enc.encode(dynamicKey).slice(0, 16);
                    let   iv    = enc.encode(BASE_IV).slice(0, 16);
                    const input = (encryptedData instanceof Uint8Array) ? encryptedData : new Uint8Array(encryptedData);
                    const output = new Uint8Array(input.length);

                    for (let i = 0; i < input.length; i++) {
                        const ks      = this._ecbBlock(keyB, iv);
                        output[i]     = ks[0] ^ input[i];
                        // CFB8 decrypt feedback: shift IV left, append ciphertext byte (not plaintext)
                        const newIv = new Uint8Array(16);
                        newIv.set(iv.subarray(1));
                        newIv[15] = input[i];
                        iv = newIv;
                    }
                    return output;
                } catch (error) {
                    log(`❌ Decryption error: ${error.message}`, 'error');
                    return null;
                }
            }
        };

        function log(message, type = 'info') {
            const timestamp = new Date().toLocaleTimeString();

            // Activity log (inside connected view)
            const logContainer = document.getElementById('logContainer');
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            entry.textContent = `[${timestamp}] ${message}`;
            logContainer.insertBefore(entry, logContainer.firstChild);
            while (logContainer.children.length > 100) {
                logContainer.removeChild(logContainer.lastChild);
            }

            // Debug panel (always visible)
            const debugContainer = document.getElementById('debugLogContainer');
            const debugEntry = document.createElement('div');
            debugEntry.className = `log-entry ${type}`;
            debugEntry.textContent = `[${timestamp}] ${message}`;
            debugContainer.insertBefore(debugEntry, debugContainer.firstChild);
            while (debugContainer.children.length > 200) {
                debugContainer.removeChild(debugContainer.lastChild);
            }

            // Update entry count badge; turn red if any errors present
            const countEl = document.getElementById('debugLogCount');
            if (countEl) {
                const n = debugContainer.children.length;
                countEl.textContent = n;
                if (type === 'error') countEl.classList.add('has-errors');
            }
        }

        function toggleDebugPanel() {
            document.getElementById('debugPanel').classList.toggle('open');
        }

        function clearDebugLog() {
            const c = document.getElementById('debugLogContainer');
            c.innerHTML = '';
            const countEl = document.getElementById('debugLogCount');
            if (countEl) { countEl.textContent = '0'; countEl.classList.remove('has-errors'); }
        }

        // Retry getPrimaryService with exponential backoff — GATT service discovery
        // on iOS/macOS can lag behind the connect callback by several hundred ms.
        async function getPrimaryServiceWithRetry(server, uuid, maxAttempts = 2, baseDelayMs = 700) {
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    const svc = await server.getPrimaryService(uuid);
                    if (attempt > 1) log(`✅ Service found on attempt ${attempt}`, 'success');
                    return svc;
                } catch (err) {
                    const isLast = attempt === maxAttempts;
                    const delay = baseDelayMs * attempt;
                    log(`⏳ Service not ready (attempt ${attempt}/${maxAttempts}): ${err.message}${isLast ? '' : ` — retrying in ${delay}ms`}`, isLast ? 'error' : 'info');
                    if (isLast) throw err;
                    await new Promise(r => setTimeout(r, delay));
                }
            }
        }

        async function discoverAllServices() {
            document.getElementById('debugPanel').classList.add('open');

            // If we already have a live GATT connection, enumerate from it directly —
            // avoids a second requestDevice/connect which often fails if the device
            // is already paired to this browser session.
            if (device && device.gatt.connected) {
                log('🔍 Using existing connection to enumerate services…', 'info');
                await enumerateServicesOnServer(device.gatt);
                return;
            }

            // If we have a stale device reference, try to reconnect it rather than
            // scanning again — avoids "connection attempt failed" from double-connect.
            if (device) {
                log('🔄 Reconnecting stale device reference…', 'info');
                try {
                    const srv = await device.gatt.connect();
                    await new Promise(r => setTimeout(r, 2000));
                    await enumerateServicesOnServer(srv);
                    device.gatt.disconnect();
                } catch (err) {
                    log(`❌ Reconnect failed: ${err.message} — try scanning fresh below`, 'error');
                    log('ℹ️ Tip: turn BLE off/on on your device then try again', 'info');
                }
                return;
            }

            // No existing reference — do a fresh scan
            log('🔍 No existing device — scanning…', 'info');
            let discoverDevice;
            try {
                discoverDevice = await navigator.bluetooth.requestDevice({
                    filters: [{ namePrefix: 'HC:' }],
                    optionalServices: [SERVICE_UUID, SERVICE_UUID_FALLBACK]
                });
                log(`📱 Device: ${discoverDevice.name}`, 'success');
                const srv = await discoverDevice.gatt.connect();
                await new Promise(r => setTimeout(r, 2000));
                await enumerateServicesOnServer(srv);
                discoverDevice.gatt.disconnect();
            } catch (err) {
                log(`❌ Discovery failed: ${err.message}`, 'error');
                log('ℹ️ Tip: turn BLE off/on on your device, wait 5s, then retry', 'info');
                if (discoverDevice?.gatt?.connected) discoverDevice.gatt.disconnect();
            }
        }

        async function enumerateServicesOnServer(gattServer) {
            try {
                const services = await gattServer.getPrimaryServices();
                if (services.length === 0) {
                    log('⚠️ No services visible — only declared optionalServices can be listed', 'error');
                    return;
                }
                log(`📋 Found ${services.length} service(s):`, 'success');
                for (const svc of services) {
                    log(`  SERVICE: ${svc.uuid}`, 'info');
                    try {
                        const chars = await svc.getCharacteristics();
                        for (const c of chars) {
                            const props = c.properties
                                ? Object.keys(c.properties).filter(p => c.properties[p]).join(', ')
                                : '?';
                            log(`    CHAR: ${c.uuid}  [${props}]`, 'info');
                        }
                    } catch (e) {
                        log(`    (chars: ${e.message})`, 'error');
                    }
                }
            } catch (err) {
                log(`❌ getPrimaryServices failed: ${err.message}`, 'error');
            }
        }

        async function connectDevice() {
            // Auto-open the debug panel so connection steps are visible immediately
            document.getElementById('debugPanel').classList.add('open');
            try {
                log('🔍 Scanning for Hanchu devices...');
                log(`ℹ️ Expecting service UUID: ${SERVICE_UUID}`);

                device = await navigator.bluetooth.requestDevice({
                    filters: [
                        { namePrefix: 'HC:' }
                    ],
                    optionalServices: [SERVICE_UUID, SERVICE_UUID_FALLBACK]
                });

                log(`📱 Found device: ${device.name}`, 'success');

                const server = await device.gatt.connect();
                log('🔗 Connected to GATT server', 'success');

                // Pause for slow devices — lets the OS finish GATT service discovery
                log('⏳ Waiting for device service discovery…');
                await new Promise(r => setTimeout(r, 2000));

                let service;
                try {
                    service = await getPrimaryServiceWithRetry(server, SERVICE_UUID);
                    log(`✅ Got BLE service (${SERVICE_UUID.slice(4, 8)})`, 'success');
                } catch (_) {
                    log(`⚠️ ${SERVICE_UUID.slice(4, 8)} not found, trying ${SERVICE_UUID_FALLBACK.slice(4, 8)}…`, 'info');
                    service = await getPrimaryServiceWithRetry(server, SERVICE_UUID_FALLBACK);
                    log(`✅ Got BLE service (${SERVICE_UUID_FALLBACK.slice(4, 8)} fallback)`, 'success');
                }

                readCharacteristic = await service.getCharacteristic(READ_CHAR_UUID);
                writeCharacteristic = await service.getCharacteristic(WRITE_CHAR_UUID);
                log(`✅ Got characteristics (R:${READ_CHAR_UUID.slice(-4)} W:${WRITE_CHAR_UUID.slice(-4)})`, 'success');

                await readCharacteristic.startNotifications();
                readCharacteristic.addEventListener('characteristicvaluechanged', handleNotification);
                log('🔔 Subscribed to notifications', 'success');

                // Update UI
                document.getElementById('statusIndicator').classList.add('connected');
                document.getElementById('statusText').textContent = `Connected to ${device.name}`;
                document.getElementById('connectBtn').style.display = 'none';
                document.getElementById('disconnectBtn').style.display = 'inline-flex';
                document.getElementById('autoRefreshToggle').style.display = 'inline-block';
                document.getElementById('autoRefreshLabel').style.display = 'inline-block';
                document.getElementById('connectedView').style.display = 'block';
                document.getElementById('deviceName').textContent = device.name;

                const deviceType = device.name.includes(P.DEVICE_TYPE_INVERTER) ? 'Inverter' : 
                                 device.name.includes(P.DEVICE_TYPE_BATTERY) ? 'Battery' : 'Unknown';
                document.getElementById('deviceType').textContent = deviceType;

                await initializeConnection();
                initializeCharts();

            } catch (error) {
                log(`❌ Connection failed: ${error.message}`, 'error');
                console.error(error);
            }
        }

        function disconnectDevice() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }

            if (device && device.gatt.connected) {
                device.gatt.disconnect();
                log('🔌 Disconnected', 'info');
            }
            
            // Reject any in-flight write confirmations
            pendingWrites.forEach(p => p.reject(new Error('disconnected')));
            pendingWrites.clear();

            device = null;
            readCharacteristic = null;
            writeCharacteristic = null;
            dynamicKey = null;
            randomFix = null;
            
            document.getElementById('statusIndicator').classList.remove('connected');
            document.getElementById('statusText').textContent = 'Disconnected';
            document.getElementById('connectBtn').style.display = 'inline-flex';
            document.getElementById('disconnectBtn').style.display = 'none';
            document.getElementById('autoRefreshToggle').style.display = 'none';
            document.getElementById('autoRefreshLabel').style.display = 'none';
            document.getElementById('connectedView').style.display = 'none';
            document.getElementById('autoRefreshCheckbox').checked = false;
        }

        async function initializeConnection() {
            // Generate a random 6-character alphanumeric string
            // Swift parseRandomFix expects: [0x05][6 UTF-8 bytes]
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            randomFix = '';
            for (let i = 0; i < 6; i++) {
                randomFix += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            log(`🔑 Generated random fix: ${randomFix}`);

            // Packet: [0x05][6 UTF-8 bytes of randomFix] = 7 bytes total
            const fixBytes = new TextEncoder().encode(randomFix); // 6 bytes (all ASCII)
            const randomFixPacket = new Uint8Array(7);
            randomFixPacket[0] = 0x05;
            randomFixPacket.set(fixBytes, 1);

            await writeCharacteristic.writeValue(randomFixPacket);
            log('📤 Sent random fix packet');

            // Derive dynamic key from the random fix and store globally
            dynamicKey = AESHelper.generateDynamicKey(randomFix);

            // Wait for key exchange, then start live polling
            setTimeout(async () => {
                await refreshStaticData();       // device info + work mode once
                await refreshAllData();          // first live snapshot
                autoRefreshInterval = setInterval(refreshAllData, 1000);
                document.getElementById('autoRefreshCheckbox').checked = true;
                log('⏰ Live refresh started (1s)', 'success');
                // Daily totals read after a short delay so device isn't flooded
                setTimeout(refreshExtendedData, 2000);
            }, 1000);
        }

        function handleNotification(event) {
            const value = event.target.value;
            const data = new Uint8Array(value.buffer);

            log(`📨 RX ${data.length} bytes | first byte: 0x${data[0]?.toString(16).padStart(2,'0') ?? '??'}`);

            try {
                // Decrypt the response
                const decrypted = AESHelper.decrypt(data);
                if (!decrypted) {
                    log('❌ Decryption failed', 'error');
                    return;
                }
                log(`🔓 Decrypted ${decrypted.length} bytes | first byte: 0x${decrypted[0]?.toString(16).padStart(2,'0') ?? '??'}`);

                // Check if LOCAL mode (starts with 0x03)
                let jsonString;
                if (decrypted[0] === 0x03) {
                    const dataLength = decrypted[4] | (decrypted[5] << 8);
                    const jsonBytes = decrypted.slice(6, 6 + dataLength);
                    jsonString = new TextDecoder().decode(jsonBytes);
                    log(`📦 LOCAL mode | declared len=${dataLength} extracted=${jsonBytes.length}`);
                } else {
                    jsonString = new TextDecoder().decode(decrypted).replace(/\0+$/, '').trim();
                    log(`📄 STANDARD mode | json len=${jsonString.length}`);
                }

                log(`📄 JSON: ${jsonString.substring(0, 120)}`);

                const parsed = JSON.parse(jsonString);
                const items = parsed.data;

                if (!items || !Array.isArray(items)) {
                    log(`⚠️ No data array in response (keys: ${Object.keys(parsed).join(', ')})`, 'error');
                    return;
                }

                log(`✅ Parsed ${items.length} items: ${items.map(i => `${i.k}=${i.v}`).join(', ')}`);

                // Resolve any pending write confirmations (v === 0 means success)
                items.forEach(item => {
                    const pending = pendingWrites.get(item.k);
                    if (pending && item.v === 0) {
                        log(`✅ Write confirmed: ${item.k}`);
                        pending.resolve();
                    }
                });

                try { populateConfigInputs(items); } catch(e) { log(`⚠️ Config populate error: ${e.message}`, 'error'); }
                updateUIWithData(parsed);

            } catch (error) {
                log(`❌ Handler error: ${error.message}`, 'error');
                console.error(error);
            }
        }

        function updateUIWithData(data) {
            if (data.data && Array.isArray(data.data)) {
                const timestamp = new Date();
                let updated = false;

                data.data.forEach(item => {
                    const key = item.k;
                    const value = item.v;
                    
                    // Map to UI and historical data
                    const mapping = {
                        [P.BATTERY_SOC]: { elem: 'soc', hist: 'soc' },
                        [P.BATTERY_TERMINAL_VOLTAGE]: { elem: 'voltage', hist: 'voltage' },
                        [P.BATTERY_CURRENT]: { elem: 'current', hist: 'current' },
                        [P.BATTERY_POWER]: { elem: 'power', hist: 'power' },
                        [P.BATTERY_TEMPERATURE]: { elem: 'temperature', hist: 'temperature' },
                        [P.PV1_VOLTAGE]: { elem: 'pv1Voltage' },
                        [P.PV1_CURRENT]: { elem: 'pv1Current' },
                        [P.PV2_VOLTAGE]: { elem: 'pv2Voltage' },
                        [P.PV2_CURRENT]: { elem: 'pv2Current' },
                        [P.PV_POWER_TOTAL]: { elem: 'pvPower', hist: 'pvPower' },
                        [P.GRID_VOLTAGE]: { elem: 'gridVoltage' },
                        [P.GRID_CURRENT]: { elem: 'gridCurrent' },
                        [P.GRID_FREQUENCY]: { elem: 'gridFrequency' },
                        [P.GRID_ACTIVE_POWER]: { elem: 'activePower', hist: 'gridPower' },
                        [P.GRID_PURCHASED_TODAY]: { elem: 'powerPurchased' },
                        [P.GRID_SOLD_TODAY]: { elem: 'powerSold' },
                        [P.BATTERY_CHARGE_TODAY]: { elem: 'battChargeToday' },
                        [P.BATTERY_DISCHARGE_TODAY]: { elem: 'battDischargeToday' },
                        [P.PV_ENERGY_TODAY]: { elem: 'pvToday' },
                        [P.PV_ENERGY_ACCUMULATED]: { elem: 'pvAccum' },
                        [P.INVERTER_SERIAL]: { elem: 'serialNumber' },
                        [P.BATTERY_SERIAL]: { elem: 'serialNumber' },
                        [P.INVERTER_FIRMWARE]: { elem: 'firmware' },
                        [P.BMS_FIRMWARE]: { elem: 'firmware' }
                    };

                    // Power on/off toggle button
                    if (key === P.POWER_ON) {
                        const btn = document.getElementById('powerToggleBtn');
                        if (btn) {
                            const isOn = parseInt(value) === 1;
                            btn.textContent = isOn ? '⏻ ON' : '⏻ OFF';
                            btn.classList.toggle('power-on',  isOn);
                            btn.classList.toggle('power-off', !isOn);
                            btn.dataset.powerState = isOn ? '1' : '0';
                        }
                        return;
                    }

                    if (mapping[key]) {
                        const elem = document.getElementById(mapping[key].elem);
                        if (elem) {
                            const display = (value == null) ? '--' : (typeof value === 'number' ? value.toFixed(2) : String(value));
                            if (elem.dataset.lastVal !== display) {
                                elem.dataset.lastVal = display;
                                const row = elem.closest('.param-item');
                                if (row) {
                                    row.classList.remove('param-updated');
                                    void row.offsetWidth; // force reflow to restart animation
                                    row.classList.add('param-updated');
                                }
                            }
                            elem.textContent = display;
                        }

                        // Store historical data
                        if (mapping[key].hist && typeof value === 'number') {
                            if (!updated) {
                                historicalData.timestamps.push(timestamp);
                                updated = true;
                            }
                            historicalData[mapping[key].hist].push(value);
                        }
                    }
                });

                // Limit historical data to last 100 points
                if (historicalData.timestamps.length > 100) {
                    Object.keys(historicalData).forEach(key => {
                        historicalData[key] = historicalData[key].slice(-100);
                    });
                }

                // Update charts
                updateCharts();
                document.getElementById('dataPointCount').textContent = historicalData.timestamps.length;
            }
        }

        async function sendCommand(command, isLocalMode = true) {
            if (!writeCharacteristic) {
                log('❌ Not connected', 'error');
                return;
            }

            try {
                const jsonString = JSON.stringify(command);
                const jsonData = new TextEncoder().encode(jsonString);
                
                let dataToEncrypt;

                if (isLocalMode) {
                    // LOCAL MODE - add packet framing
                    const packet = new Uint8Array(6 + jsonData.length);
                    packet[0] = 0x03; // Command type
                    packet[1] = 0x00; // Packet type (0 = last/only)
                    packet[2] = 0x00; // Index low
                    packet[3] = 0x00; // Index high
                    packet[4] = jsonData.length & 0xFF; // Length low
                    packet[5] = (jsonData.length >> 8) & 0xFF; // Length high
                    packet.set(jsonData, 6);
                    dataToEncrypt = packet;
                    log('📦 Using LOCAL mode (framed packet)');
                } else {
                    // STANDARD MODE - raw JSON
                    dataToEncrypt = jsonData;
                    log('📄 Using STANDARD mode (raw JSON)');
                }

                // Encrypt and send
                const encrypted = AESHelper.encrypt(dataToEncrypt);
                if (!encrypted) {
                    log('❌ Encryption failed', 'error');
                    return;
                }

                await writeCharacteristic.writeValue(encrypted);
                log(`📤 Sent ${encrypted.length} bytes`, 'success');
                
            } catch (error) {
                log(`❌ Send failed: ${error.message}`, 'error');
                console.error(error);
            }
        }

        async function readParameter(key) {
            const command = {
                cmd: 'local',
                act: '1', // Read
                tid: '10001',
                data: [{ k: key }]
            };

            await sendCommand(command, false); // STANDARD mode - raw JSON
            log(`📖 Reading: ${key}`);
        }

        async function writeParameter(key, value) {
            // Register confirmation promise before sending so no response is missed
            const confirmation = new Promise((resolve, reject) => {
                const timeoutId = setTimeout(() => {
                    pendingWrites.delete(key);
                    reject(new Error('timeout'));
                }, 5000);

                pendingWrites.set(key, {
                    resolve() { clearTimeout(timeoutId); pendingWrites.delete(key); resolve(); },
                    reject(e)  { clearTimeout(timeoutId); pendingWrites.delete(key); reject(e); }
                });
            });

            const command = {
                cmd: 'local',
                act: '3', // Write
                tid: '10001',
                data: [{ k: key, v: value }]
            };

            await sendCommand(command, false);
            log(`✏️ Writing ${key} = ${value}…`);

            try {
                await confirmation;
                log(`✅ ${key} confirmed (v=0)`, 'success');
                return true;
            } catch (err) {
                log(`⚠️ Write ${key} ${err.message === 'timeout' ? 'timed out' : `failed: ${err.message}`}`, 'error');
                return false;
            }
        }

        // Send all key-value pairs in ONE command, await all confirmations concurrently
        async function writeParameterBatch(pairs) {
            if (!writeCharacteristic || pairs.length === 0) return;

            // Register ALL pending promises before sending — no response can arrive early
            const confirmations = pairs.map(({ k }) => new Promise((resolve, reject) => {
                const timeoutId = setTimeout(() => {
                    pendingWrites.delete(k);
                    reject(new Error('timeout'));
                }, 8000);
                pendingWrites.set(k, {
                    resolve() { clearTimeout(timeoutId); pendingWrites.delete(k); resolve(); },
                    reject(e)  { clearTimeout(timeoutId); pendingWrites.delete(k); reject(e); }
                });
            }));

            // One BLE packet for the whole batch
            await sendCommand({
                cmd: 'local',
                act: '3',
                tid: '10001',
                data: pairs
            }, false);
            log(`✏️ Batch writing ${pairs.length} parameters…`);

            // Wait for every confirmation (don't short-circuit on failure)
            const results = await Promise.allSettled(confirmations);
            const failed  = results.filter(r => r.status === 'rejected');

            if (failed.length === 0) {
                log(`✅ All ${pairs.length} parameters confirmed`, 'success');
                return true;
            } else {
                failed.forEach(r => {
                    const k = pairs[results.indexOf(r)]?.k ?? '?';
                    log(`⚠️ ${k}: ${r.reason?.message}`, 'error');
                });
                log(`⚠️ ${pairs.length - failed.length}/${pairs.length} confirmed`, 'error');
                return false;
            }
        }

        async function refreshAllData() {
            if (!device || !device.gatt.connected) return;
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: [P.BATTERY_SOC,P.BATTERY_TERMINAL_VOLTAGE,P.BATTERY_CURRENT,P.BATTERY_POWER,P.BATTERY_TEMPERATURE,
                       P.PV1_VOLTAGE,P.PV1_CURRENT,P.PV2_VOLTAGE,P.PV2_CURRENT,P.PV_POWER_TOTAL,
                       P.GRID_VOLTAGE,P.GRID_CURRENT,P.GRID_FREQUENCY,P.GRID_ACTIVE_POWER].map(k => ({ k }))
            }, false);
        }

        // Daily totals + power state — read once after connect, not every second
        async function refreshExtendedData() {
            if (!device || !device.gatt.connected) return;
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: [P.GRID_PURCHASED_TODAY,P.GRID_SOLD_TODAY,P.BATTERY_CHARGE_TODAY,P.BATTERY_DISCHARGE_TODAY,P.PV_ENERGY_TODAY,P.PV_ENERGY_ACCUMULATED,P.POWER_ON].map(k => ({ k }))
            }, false);
        }

        // Request static device info once (serial, firmware) — one packet
        async function refreshStaticData() {
            await sendCommand({
                cmd: 'local',
                act: '1',
                tid: '10001',
                data: [P.INVERTER_SERIAL, P.BATTERY_SERIAL, P.INVERTER_FIRMWARE, P.BMS_FIRMWARE, P.WORK_MODE].map(k => ({ k }))
            }, false);
        }

        function toggleAutoRefresh() {
            const enabled = document.getElementById('autoRefreshCheckbox').checked;

            if (enabled) {
                log('⏰ Auto-refresh enabled (1s interval)', 'success');
                autoRefreshInterval = setInterval(refreshAllData, 1000);
            } else {
                log('⏸️ Auto-refresh disabled');
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
        }

        function setWorkMode(mode) {
            writeParameter(P.WORK_MODE, mode);
            const modes = ['Self-Consumption', 'Backup', 'User Defined', 'Off-Grid'];
            log(`🔄 Setting work mode: ${modes[mode]}`);
        }

        // ── Button feedback helpers ───────────────────────

        function setButtonState(btn, state) {
            if (!btn) return;
            if (state === 'loading') {
                btn.dataset.origHtml = btn.innerHTML;
                btn.innerHTML = 'Applying…';
                btn.classList.add('btn-loading');
            } else {
                btn.classList.remove('btn-loading');
                const ok = state === 'success';
                btn.innerHTML = ok ? '✅ Applied' : '❌ Failed — check log';
                btn.classList.add(ok ? 'btn-write-success' : 'btn-write-error');
                setTimeout(() => {
                    btn.classList.remove('btn-write-success', 'btn-write-error');
                    btn.innerHTML = btn.dataset.origHtml || btn.innerHTML;
                    delete btn.dataset.origHtml;
                }, ok ? 2500 : 3500);
            }
        }

        // ── Config tab ────────────────────────────────────

        function switchConfigMode(mode) {
            document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
            document.querySelector(`.mode-btn[data-mode="${mode}"]`).classList.add('active');
            document.querySelectorAll('.config-section').forEach(s => s.classList.remove('active'));
            document.getElementById(`config-${mode}`).classList.add('active');
        }

        function togglePeriod(checkbox, startId, endId) {
            const start = document.getElementById(startId);
            const end   = document.getElementById(endId);
            start.disabled = !checkbox.checked;
            end.disabled   = !checkbox.checked;
        }

        // ── Period card helpers ───────────────────────────

        function togglePeriodCard(checkbox, cardId, startId, endId) {
            const card  = document.getElementById(cardId);
            const start = document.getElementById(startId);
            const end   = document.getElementById(endId);
            card?.classList.toggle('disabled-period', !checkbox.checked);
            if (start) start.disabled = !checkbox.checked;
            if (end)   end.disabled   = !checkbox.checked;
            updateTimeline();
        }

        function onTimeInput(durId, startId, endId) {
            const start = timeToMinutes(document.getElementById(startId)?.value || '00:00');
            const end   = timeToMinutes(document.getElementById(endId)?.value   || '00:00');
            const dur   = Math.max(0, end - start);
            const el    = document.getElementById(durId);
            if (el) el.textContent = dur > 0
                ? `${Math.floor(dur / 60)}h ${(dur % 60).toString().padStart(2, '0')}m`
                : '—';
            updateTimeline();
        }

        function minutesToTime(minutes) {
            const m = Math.max(0, Math.min(1439, parseInt(minutes) || 0));
            return `${Math.floor(m / 60).toString().padStart(2, '0')}:${(m % 60).toString().padStart(2, '0')}`;
        }

        function updateTimeline() {
            const segs = [
                { s: 'ud-p1-start', e: 'ud-p1-end', id: 'tl-p1' },
                { s: 'ud-p2-start', e: 'ud-p2-end', id: 'tl-p2' },
                { s: 'ud-p3-start', e: 'ud-p3-end', id: 'tl-p3' },
                { s: 'ud-p4-start', e: 'ud-p4-end', id: 'tl-p4' },
                { s: 'ud-p5-start', e: 'ud-p5-end', id: 'tl-p5' },
                { s: 'ud-p6-start', e: 'ud-p6-end', id: 'tl-p6' },
            ];
            segs.forEach(({ s, e, id }) => {
                const seg   = document.getElementById(id);
                const sEl   = document.getElementById(s);
                const eEl   = document.getElementById(e);
                if (!seg || !sEl || !eEl) return;
                const sMin  = timeToMinutes(sEl.value);
                const eMin  = timeToMinutes(eEl.value);
                const valid = !sEl.disabled && eMin > sMin;
                seg.style.left  = valid ? `${(sMin / 1440) * 100}%` : '0%';
                seg.style.width = valid ? `${((eMin - sMin) / 1440) * 100}%` : '0%';
            });
        }

        // Read all config parameters from device
        async function readConfigParams() {
            if (!device?.gatt?.connected) return;
            log('📖 Reading config parameters…');
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: [P.WORK_MODE,
                       P.CHARGE_P1_START,P.CHARGE_P1_END,P.CHARGE_P2_START,P.CHARGE_P2_END,P.CHARGE_P3_START,P.CHARGE_P3_END,
                       P.DISCHARGE_P1_START,P.DISCHARGE_P1_END,P.DISCHARGE_P2_START,P.DISCHARGE_P2_END,P.DISCHARGE_P3_START,P.DISCHARGE_P3_END,
                       P.CHARGE_POWER_LIMIT,P.DISCHARGE_POWER_LIMIT,P.MAX_SOC_LIMIT,P.CHARGE_TO_SOC,P.DISCHARGE_TO_SOC,P.MIN_SOC_CUTOFF
                      ].map(k => ({ k }))
            }, false);
        }

        // Populate config form fields from incoming BLE data
        function populateConfigInputs(items) {
            if (!items?.length) return;
            // Has to start at 1
            const modeMap = { 1: 'selfconsumption', 2: 'backup', 3: 'userdefined', 4: 'offgrid' };
            let touchedTimeInput = false;

            items.forEach(({ k, v }) => {
                if (k === P.WORK_MODE) {
                    const idx      = parseInt(v);
                    const modeKey  = modeMap[idx];
                    const names    = ['Self-Consumption', 'Backup', 'User Defined', 'Off-Grid'];
                    const badges   = ['badge-green', 'badge-blue', 'badge-purple', 'badge-orange'];

                    // Monitor tab badge
                    const el = document.getElementById('activeWorkMode');
                    if (el) {
                        el.textContent = names[idx] ?? `Mode ${idx}`;
                        el.className   = `badge ${badges[idx] ?? 'badge-blue'}`;
                    }

                    // Config tab "Active" pill — mark only the matching button
                    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('device-active'));
                    if (modeKey) document.querySelector(`.mode-btn[data-mode="${modeKey}"]`)?.classList.add('device-active');

                    if (modeKey) switchConfigMode(modeKey);
                    return;
                }

                document.querySelectorAll(`[data-param="${k}"]`).forEach(input => {
                    if (input.type === 'time') {
                        const t = minutesToTime(parseInt(v) || 0);
                        if (input.value !== t) {
                            input.value = t;
                            input.dispatchEvent(new Event('input')); // updates duration badge
                            touchedTimeInput = true;
                        }
                    } else if (input.type === 'range') {
                        input.value = v;
                        input.dispatchEvent(new Event('input')); // updates label display
                    }
                });

                // Re-enable period card if device reports a non-zero period
                if ([P.CHARGE_P2_START,P.CHARGE_P3_START,P.DISCHARGE_P1_START,P.DISCHARGE_P2_START,P.DISCHARGE_P3_START].includes(k) && parseInt(v) > 0) {
                    const cardMap = { [P.CHARGE_P2_START]:'card-p2', [P.CHARGE_P3_START]:'card-p3', [P.DISCHARGE_P1_START]:'card-p4', [P.DISCHARGE_P2_START]:'card-p5', [P.DISCHARGE_P3_START]:'card-p6' };
                    const startMap = { [P.CHARGE_P2_START]:'ud-p2-start', [P.CHARGE_P3_START]:'ud-p3-start', [P.DISCHARGE_P1_START]:'ud-p4-start', [P.DISCHARGE_P2_START]:'ud-p5-start', [P.DISCHARGE_P3_START]:'ud-p6-start' };
                    const endMap   = { [P.CHARGE_P2_START]:'ud-p2-end',   [P.CHARGE_P3_START]:'ud-p3-end',   [P.DISCHARGE_P1_START]:'ud-p4-end',   [P.DISCHARGE_P2_START]:'ud-p5-end',   [P.DISCHARGE_P3_START]:'ud-p6-end' };
                    const card  = document.getElementById(cardMap[k]);
                    const startEl = document.getElementById(startMap[k]);
                    const endEl   = document.getElementById(endMap[k]);
                    if (card) {
                        const cb = card.querySelector('input[type="checkbox"]');
                        if (cb && !cb.checked) {
                            cb.checked = true;
                            card.classList.remove('disabled-period');
                            if (startEl) startEl.disabled = false;
                            if (endEl)   endEl.disabled   = false;
                        }
                    }
                }
            });

            if (touchedTimeInput) updateTimeline();
        }

        function timeToMinutes(timeStr) {
            if (!timeStr) return 0;
            const [h, m] = timeStr.split(':').map(Number);
            return h * 60 + m;
        }

        async function applyModeConfig(modeKey, modeNum, btn) {
            if (!device || !device.gatt.connected) {
                log('❌ Not connected', 'error');
                return;
            }
            setButtonState(btn, 'loading');

            const section  = document.getElementById(`config-${modeKey}`);
            const modeNames = { selfconsumption: 'Self-Consumption', backup: 'Backup', userdefined: 'User Defined', offgrid: 'Off-Grid' };
            log(`🔧 Applying ${modeNames[modeKey]} (P651=${modeNum})…`);

            // Params forced to 0 by disabled period toggles
            const forcedZero = new Set();
            section.querySelectorAll('input[data-period-for]').forEach(cb => {
                if (!cb.checked) cb.dataset.periodFor.split(',').forEach(p => forcedZero.add(p.trim()));
            });

            // Collect all {k, v} pairs from data-param inputs
            const pairs = [];
            section.querySelectorAll('[data-param]').forEach(el => {
                const k = el.dataset.param;
                let v;
                if (forcedZero.has(k))  v = 0;
                else if (el.type === 'time') v = timeToMinutes(el.value);
                else v = parseInt(el.value) || 0;
                pairs.push({ k, v });
            });

            // 1. Set work mode first and wait for confirmation
            const modeOk = await writeParameter(P.WORK_MODE, modeNum);

            // 2. Send all mode-specific parameters in one batch
            const paramsOk = await writeParameterBatch(pairs);

            const ok = modeOk && paramsOk;
            setButtonState(btn, ok ? 'success' : 'error');
            if (ok) {
                log(`✅ ${modeNames[modeKey]} configuration applied`, 'success');
                await readConfigParams();
            }
        }

        async function writePowerLimits(btn) {
            setButtonState(btn, 'loading');
            const ok = await writeParameterBatch([
                { k: P.CHARGE_POWER_LIMIT, v: parseInt(document.getElementById('chargePowerSlider').value) },
                { k: P.DISCHARGE_POWER_LIMIT, v: parseInt(document.getElementById('dischargePowerSlider').value) }
            ]);
            setButtonState(btn, ok ? 'success' : 'error');
        }

        async function toggleDevicePower(btn) {
            if (!device?.gatt?.connected) { log('❌ Not connected', 'error'); return; }
            const currentState = parseInt(btn.dataset.powerState ?? '1');
            const newState = currentState === 1 ? 0 : 1;
            setButtonState(btn, 'loading');
            const ok = await writeParameter(P.POWER_ON, newState);
            setButtonState(btn, ok ? 'success' : 'error');
            if (ok) {
                btn.dataset.powerState = String(newState);
                const isOn = newState === 1;
                btn.textContent = isOn ? '⏻ ON' : '⏻ OFF';
                btn.classList.toggle('power-on',  isOn);
                btn.classList.toggle('power-off', !isOn);
                log(`⏻ Device powered ${isOn ? 'ON' : 'OFF'}`, isOn ? 'success' : 'warning');
            }
        }

        function updateSliderValue(elementId, value, unit) {
            document.getElementById(elementId).textContent = value + unit;
        }

        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(tabName + 'Tab').classList.add('active');

            if (tabName === 'config' && device?.gatt?.connected) {
                readConfigParams();
            }
        }

        // Chart functions
        function initializeCharts() {
            if (typeof Chart === 'undefined') {
                log('⚠️ Chart.js not loaded - Analytics disabled', 'error');
                console.error('Chart.js failed to load. Charts will not be available.');
                return;
            }

            const chartConfig = {
                type: 'line',
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { intersect: false, mode: 'index' },
                    plugins: {
                        legend: { display: true, position: 'top' }
                    },
                    scales: {
                        x: { display: true },
                        y: { display: true }
                    }
                }
            };

            // Battery Chart
            batteryChart = new Chart(document.getElementById('batteryChart'), {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'SOC (%)',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: '#10b98120'
                    }, {
                        label: 'Voltage (V)',
                        data: [],
                        borderColor: '#3b82f6',
                        backgroundColor: '#3b82f620'
                    }]
                }
            });

            // Solar Chart
            solarChart = new Chart(document.getElementById('solarChart'), {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'PV Power (W)',
                        data: [],
                        borderColor: '#f59e0b',
                        backgroundColor: '#f59e0b20'
                    }]
                }
            });

            // Grid Chart
            gridChart = new Chart(document.getElementById('gridChart'), {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Grid Power (W)',
                        data: [],
                        borderColor: '#8b5cf6',
                        backgroundColor: '#8b5cf620'
                    }]
                }
            });

            // Temperature Chart
            temperatureChart = new Chart(document.getElementById('temperatureChart'), {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Temperature (°C)',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: '#ef444420'
                    }]
                }
            });
        }

        function updateCharts() {
            if (!batteryChart || typeof Chart === 'undefined') return;

            const labels = historicalData.timestamps.map(t => t.toLocaleTimeString());

            // Battery Chart
            batteryChart.data.labels = labels;
            batteryChart.data.datasets[0].data = historicalData.soc;
            batteryChart.data.datasets[1].data = historicalData.voltage;
            batteryChart.update('none');

            // Solar Chart
            solarChart.data.labels = labels;
            solarChart.data.datasets[0].data = historicalData.pvPower;
            solarChart.update('none');

            // Grid Chart
            gridChart.data.labels = labels;
            gridChart.data.datasets[0].data = historicalData.gridPower;
            gridChart.update('none');

            // Temperature Chart
            temperatureChart.data.labels = labels;
            temperatureChart.data.datasets[0].data = historicalData.temperature;
            temperatureChart.update('none');
        }

        function exportToCSV() {
            const headers = ['Timestamp', 'SOC(%)', 'Voltage(V)', 'Current(A)', 'Power(W)', 'Temperature(°C)', 'PV_Power(W)', 'Grid_Power(W)'];
            const rows = historicalData.timestamps.map((time, i) => [
                time.toISOString(),
                historicalData.soc[i] || '',
                historicalData.voltage[i] || '',
                historicalData.current[i] || '',
                historicalData.power[i] || '',
                historicalData.temperature[i] || '',
                historicalData.pvPower[i] || '',
                historicalData.gridPower[i] || ''
            ]);

            const csv = [headers, ...rows].map(row => row.join(',')).join('\n');
            downloadFile(csv, 'hanchu-data.csv', 'text/csv');
            log('📥 Exported to CSV', 'success');
        }

        function exportToJSON() {
            const json = JSON.stringify(historicalData, null, 2);
            downloadFile(json, 'hanchu-data.json', 'application/json');
            log('📥 Exported to JSON', 'success');
        }

        function downloadFile(content, filename, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        }

        function clearHistory() {
            if (!confirm('Clear all historical data?')) return;
            
            Object.keys(historicalData).forEach(key => {
                historicalData[key] = [];
            });
            updateCharts();
            document.getElementById('dataPointCount').textContent = '0';
            log('🗑️ History cleared', 'info');
        }

        // Check Web Bluetooth support
        if (!navigator.bluetooth) {
            alert('⚠️ Web Bluetooth is not supported. Please use Chrome, Edge, or Opera.');
        }

        // Verify required libraries loaded
        window.addEventListener('DOMContentLoaded', () => {
            updateTimeline(); // draw default period segments
            const issues = [];
            
            if (typeof CryptoJS === 'undefined') {
                issues.push('❌ CryptoJS failed to load - Encryption will not work');
            } else {
                console.log('✅ CryptoJS loaded successfully');
            }
            
            if (typeof Chart === 'undefined') {
                issues.push('⚠️ Chart.js failed to load - Analytics charts disabled');
                // Hide analytics tab if Chart.js failed
                document.querySelector('.tab:nth-child(3)')?.remove();
            } else {
                console.log('✅ Chart.js loaded successfully');
            }
            
            if (issues.length > 0) {
                console.error('Library Loading Issues:', issues);
                alert(issues.join('\n'));
            }
        });
