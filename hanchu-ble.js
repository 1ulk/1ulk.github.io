        // BLE Service and Characteristic UUIDs
        // Primary: ffff (confirmed on this device). Fallback: ff00 (other units).
        const SERVICE_UUID          = '0000ffff-0000-1000-8000-00805f9b34fb';
        const SERVICE_UUID_FALLBACK = '0000ff00-0000-1000-8000-00805f9b34fb';
        const READ_CHAR_UUID        = '0000ff01-0000-1000-8000-00805f9b34fb';
        const WRITE_CHAR_UUID       = '0000ff02-0000-1000-8000-00805f9b34fb';

        // BLE connection state
        let device = null;
        let readCharacteristic = null;
        let writeCharacteristic = null;
        let autoRefreshInterval = null;
        let userInitiatedDisconnect = false;

        // Pending write confirmations: key → { resolve, reject, timeoutId }
        const pendingWrites = new Map();

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
            userInitiatedDisconnect = false;
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
                readCharacteristic.removeEventListener('characteristicvaluechanged', handleNotification);
                readCharacteristic.addEventListener('characteristicvaluechanged', handleNotification);
                log('🔔 Subscribed to notifications', 'success');

                device.removeEventListener('gattserverdisconnected', handleUnexpectedDisconnect);
                device.addEventListener('gattserverdisconnected', handleUnexpectedDisconnect);

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

        async function handleUnexpectedDisconnect() {
            if (userInitiatedDisconnect) return;

            log('⚠️ Device disconnected unexpectedly — attempting reconnect…', 'error');
            document.getElementById('statusIndicator').classList.remove('connected');
            document.getElementById('statusText').textContent = 'Reconnecting…';

            const maxAttempts = 5;
            for (let attempt = 1; attempt <= maxAttempts; attempt++) {
                await new Promise(r => setTimeout(r, 2000 * attempt));
                try {
                    log(`🔄 Reconnect attempt ${attempt}/${maxAttempts}…`);
                    const server = await device.gatt.connect();
                    log('🔗 Reconnected to GATT server', 'success');

                    await new Promise(r => setTimeout(r, 2000));

                    let service;
                    try {
                        service = await getPrimaryServiceWithRetry(server, SERVICE_UUID);
                    } catch (_) {
                        service = await getPrimaryServiceWithRetry(server, SERVICE_UUID_FALLBACK);
                    }

                    readCharacteristic  = await service.getCharacteristic(READ_CHAR_UUID);
                    writeCharacteristic = await service.getCharacteristic(WRITE_CHAR_UUID);
                    log('✅ Characteristics restored', 'success');

                    await readCharacteristic.startNotifications();
                    readCharacteristic.removeEventListener('characteristicvaluechanged', handleNotification);
                    readCharacteristic.addEventListener('characteristicvaluechanged', handleNotification);
                    log('🔔 Notifications re-subscribed', 'success');

                    device.removeEventListener('gattserverdisconnected', handleUnexpectedDisconnect);
                    device.addEventListener('gattserverdisconnected', handleUnexpectedDisconnect);

                    document.getElementById('statusIndicator').classList.add('connected');
                    document.getElementById('statusText').textContent = `Connected to ${device.name}`;

                    // Re-run key exchange so encrypted comms work again
                    await initializeConnection();
                    log('✅ Reconnected successfully', 'success');
                    return;
                } catch (err) {
                    log(`❌ Reconnect attempt ${attempt} failed: ${err.message}`, 'error');
                }
            }

            log('❌ Could not reconnect after multiple attempts — please reconnect manually', 'error');
            disconnectDevice();
        }

        function disconnectDevice() {
            userInitiatedDisconnect = true;

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

            document.getElementById('statusIndicator').classList.remove('connected');
            document.getElementById('statusText').textContent = 'Disconnected';
            document.getElementById('connectBtn').style.display = 'inline-flex';
            document.getElementById('disconnectBtn').style.display = 'none';
            document.getElementById('autoRefreshToggle').style.display = 'none';
            document.getElementById('autoRefreshLabel').style.display = 'none';
            document.getElementById('autoRefreshCheckbox').checked = false;
        }

        async function initializeConnection() {
            randomFixPacket = AESHelper.init()
            await writeCharacteristic.writeValue(randomFixPacket);
            
            log('📤 Sent random fix packet');
            
            // Wait for key exchange, then start live polling
            setTimeout(async () => {
                await refreshStaticData();       // device info + work mode once
                await refreshAllData();          // first live snapshot
                log('✅ Initial data loaded — auto-refresh is off. Enable it to poll every 5s.');
                // Daily totals read after a short delay so device isn't flooded
                setTimeout(refreshExtendedData, 2000);
            }, 1000);
        }

        function handleNotification(event) {
            const value = event.target.value;
            const data = new Uint8Array(value.buffer);

            //log(`📨 RX ${data.length} bytes | first byte: 0x${data[0]?.toString(16).padStart(2,'0') ?? '??'}`);

            try {
                // Decrypt the response
                const decrypted = AESHelper.decrypt(data);
                if (!decrypted) {
                    log('❌ Decryption failed', 'error');
                    return;
                }
                //log(`🔓 Decrypted ${decrypted.length} bytes | first byte: 0x${decrypted[0]?.toString(16).padStart(2,'0') ?? '??'}`);

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

                //log(`📄 JSON: ${jsonString.substring(0, 120)}`);

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
                    //log('📄 Using STANDARD mode (raw JSON)');
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
            if (!device || !device.gatt.connected) {
                log('⚠️ refreshAllData skipped — device not connected', 'error');
                return;
            }
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: [ P.BATTERY_SOC,
                        P.BATTERY_TERMINAL_VOLTAGE,
                        P.BATTERY_CURRENT,
                        P.BATTERY_POWER,
                        P.BATTERY_TEMPERATURE,
                        P.PV1_VOLTAGE,
                        P.PV1_CURRENT,
                        P.PV2_VOLTAGE,
                        P.PV2_CURRENT,
                        P.PV_POWER_TOTAL,
                        P.LOAD,
                        P.GRID_VOLTAGE,
                        P.GRID_CURRENT,
                        P.GRID_FREQUENCY,
                        P.GRID_ACTIVE_POWER,
                        P.WORK_MODE
                    ].map(k => ({ k }))
            }, false);
        }

        // Daily totals + power state — read once after connect, not every second
        async function refreshExtendedData() {
            if (!device || !device.gatt.connected) return;
            await sendCommand({
                cmd: 'local', act: '1',
                tid: '10001',
                data: [ P.GRID_PURCHASED_TODAY,
                        P.GRID_SOLD_TODAY,
                        P.BATTERY_CHARGE_TODAY,
                        P.BATTERY_DISCHARGE_TODAY,
                        P.PV_ENERGY_TODAY,
                        P.PV_ENERGY_ACCUMULATED,
                        P.POWER_ON
                    ].map(k => ({ k }))
            }, false);
        }

        // Request static device info once (serial, firmware) — one packet
        async function refreshStaticData() {
            await sendCommand({
                cmd: 'local',
                act: '1',
                tid: '10001',
                data: [P.INVERTER_SERIAL, P.BATTERY_SERIAL, P.INVERTER_FIRMWARE, P.BMS_FIRMWARE].map(k => ({ k }))
            }, false);
        }

        function toggleAutoRefresh() {
            const enabled = document.getElementById('autoRefreshCheckbox').checked;

            if (enabled) {
                if (!device || !device.gatt.connected) {
                    log('⚠️ Cannot start auto-refresh — device not connected', 'error');
                    return;
                }
                log('⏰ Auto-refresh enabled (5s interval)', 'success');
                autoRefreshInterval = setInterval(refreshAllData, 5000);
                refreshAllData(); // immediate first tick so it doesn't feel broken
            } else {
                log('⏸️ Auto-refresh disabled');
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
        }
