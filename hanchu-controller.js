        // BLE Service and Characteristic UUIDs
        const SERVICE_UUID = '0000ff00-0000-1000-8000-00805f9b34fb';
        const READ_CHAR_UUID = '0000ff01-0000-1000-8000-00805f9b34fb';
        const WRITE_CHAR_UUID = '0000ff02-0000-1000-8000-00805f9b34fb';

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
            const logContainer = document.getElementById('logContainer');
            const timestamp = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            entry.textContent = `[${timestamp}] ${message}`;
            logContainer.insertBefore(entry, logContainer.firstChild);
            
            while (logContainer.children.length > 100) {
                logContainer.removeChild(logContainer.lastChild);
            }
        }

        async function connectDevice() {
            try {
                log('🔍 Scanning for Hanchu devices...');
                
                device = await navigator.bluetooth.requestDevice({
                    filters: [
                        { namePrefix: 'HC:' }
                    ],
                    optionalServices: [SERVICE_UUID]
                });

                log(`📱 Found device: ${device.name}`, 'success');

                const server = await device.gatt.connect();
                log('🔗 Connected to GATT server', 'success');

                const service = await server.getPrimaryService(SERVICE_UUID);
                log('✅ Got BLE service', 'success');

                readCharacteristic = await service.getCharacteristic(READ_CHAR_UUID);
                writeCharacteristic = await service.getCharacteristic(WRITE_CHAR_UUID);
                log('✅ Got characteristics', 'success');

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

                const deviceType = device.name.includes('L110') ? 'Inverter' : 
                                 device.name.includes('L101') ? 'Battery' : 'Unknown';
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
                        'P071': { elem: 'soc', hist: 'soc' },
                        'B035': { elem: 'voltage', hist: 'voltage' },
                        'B043': { elem: 'current', hist: 'current' },
                        'P069': { elem: 'power', hist: 'power' },
                        'P070': { elem: 'temperature', hist: 'temperature' },
                        'P024': { elem: 'pv1Voltage' },
                        'P025': { elem: 'pv1Current' },
                        'P026': { elem: 'pv2Voltage' },
                        'P027': { elem: 'pv2Current' },
                        'P060': { elem: 'pvPower', hist: 'pvPower' },
                        'P044': { elem: 'gridVoltage' },
                        'P045': { elem: 'gridCurrent' },
                        'P053': { elem: 'gridFrequency' },
                        'P055': { elem: 'activePower', hist: 'gridPower' },
                        'P638': { elem: 'powerPurchased' },
                        'P639': { elem: 'powerSold' },
                        'P075': { elem: 'battChargeToday' },
                        'P076': { elem: 'battDischargeToday' },
                        'P061': { elem: 'pvToday' },
                        'P062': { elem: 'pvAccum' },
                        'P002': { elem: 'serialNumber' },
                        'B002': { elem: 'serialNumber' },
                        'P006': { elem: 'firmware' },
                        'L023': { elem: 'firmware' }
                    };

                    // Power on/off toggle button
                    if (key === 'P500') {
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
                data: ['B034','B035','B043','P069','P070',
                       'P024','P025','P026','P027','P060',
                       'P044','P045','P053','P055'].map(k => ({ k }))
            }, false);
        }

        // Daily totals + power state — read once after connect, not every second
        async function refreshExtendedData() {
            if (!device || !device.gatt.connected) return;
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: ['P638','P639','P075','P076','P061','P062','P500'].map(k => ({ k }))
            }, false);
        }

        // Request static device info once (serial, firmware) — one packet
        async function refreshStaticData() {
            await sendCommand({
                cmd: 'local',
                act: '1',
                tid: '10001',
                data: ['P002', 'B002', 'P006', 'L023', 'P651'].map(k => ({ k }))
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
            writeParameter('P651', mode);
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
                data: ['P651',
                       'L005','L006','L007','L008','L009','L010',
                       'L011','L012','L013','L014','L015','L016',
                       'L017','L018','L074','P647','P648','P772'
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
                if (k === 'P651') {
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
                if (['L007','L009','L011','L013','L015'].includes(k) && parseInt(v) > 0) {
                    const cardMap = { L007:'card-p2', L009:'card-p3', L011:'card-p4', L013:'card-p5', L015:'card-p6' };
                    const startMap = { L007:'ud-p2-start', L009:'ud-p3-start', L011:'ud-p4-start', L013:'ud-p5-start', L015:'ud-p6-start' };
                    const endMap   = { L007:'ud-p2-end',   L009:'ud-p3-end',   L011:'ud-p4-end',   L013:'ud-p5-end',   L015:'ud-p6-end' };
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
            const modeOk = await writeParameter('P651', modeNum);

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
                { k: 'L017', v: parseInt(document.getElementById('chargePowerSlider').value) },
                { k: 'L018', v: parseInt(document.getElementById('dischargePowerSlider').value) }
            ]);
            setButtonState(btn, ok ? 'success' : 'error');
        }

        async function toggleDevicePower(btn) {
            if (!device?.gatt?.connected) { log('❌ Not connected', 'error'); return; }
            const currentState = parseInt(btn.dataset.powerState ?? '1');
            const newState = currentState === 1 ? 0 : 1;
            setButtonState(btn, 'loading');
            const ok = await writeParameter('P500', newState);
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
