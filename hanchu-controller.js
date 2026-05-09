        // Historical data storage
        let historicalData = {
            timestamps: [],
            soc: [],
            voltage: [],
            current: [],
            power: [],
            pvPower: [],
            activePower: [],
            currentLoad: []
        };

        // Charts
        let powerOverviewChart = null;
        let batteryChart = null;

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
                        [P.LOAD]: { elem: 'currentLoad', hist: 'currentLoad' },
                        [P.BATTERY_TEMPERATURE]: { elem: 'temperature', hist: 'temperature' },
                        [P.PV1_VOLTAGE]: { elem: 'pv1Voltage' },
                        [P.PV1_CURRENT]: { elem: 'pv1Current' },
                        [P.PV2_VOLTAGE]: { elem: 'pv2Voltage' },
                        [P.PV2_CURRENT]: { elem: 'pv2Current' },
                        [P.PV_POWER_TOTAL]: { elem: 'pvPower', hist: 'pvPower' },
                        [P.GRID_VOLTAGE]: { elem: 'gridVoltage' },
                        [P.GRID_CURRENT]: { elem: 'gridCurrent' },
                        [P.GRID_FREQUENCY]: { elem: 'gridFrequency' },
                        [P.GRID_ACTIVE_POWER]: { elem: 'activePower', hist: 'activePower' },
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

                // Update charts and energy flow diagram
                updateCharts();
                updateEnergyFlow();
                document.getElementById('dataPointCount').textContent = historicalData.timestamps.length;
            }
        }

        async function setWorkMode(modeStr) {
            const modes = ['undefined', 'selfconsumption', 'backup', 'userdefined', 'offgrid'];
            let modeNum = modes.indexOf(modeStr)
            if (modeNum <= 0){
                log(`Modenum '${modeStr}' unknown`)
                return false;
            }
            return await writeParameter(P.WORK_MODE, modeNum);
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
            await readConfigParams(mode)
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
        function secondsToTime(seconds) {
            return minutesToTime(seconds / 60)
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
        async function readConfigParams(mode) {
            if (!device?.gatt?.connected) return;
            log('📖 Reading config parameters…');
            
            dataKeys = [P.CHARGE_POWER_LIMIT,
                        P.DISCHARGE_POWER_LIMIT,
                        P.MAX_SOC_LIMIT,
                        P.CHARGE_TO_SOC,
                        P.DISCHARGE_TO_SOC,
                        P.MIN_SOC_CUTOFF]
            
            if (mode == 'userdefined'){
                // userdefined
                dataKeys += [
                        P.CHARGE_P1_START,
                        P.CHARGE_P1_END,
                        P.CHARGE_P2_START,
                        P.CHARGE_P2_END,
                        P.CHARGE_P3_START,
                        P.CHARGE_P3_END,
                        P.DISCHARGE_P1_START,
                        P.DISCHARGE_P1_END,
                        P.DISCHARGE_P2_START,
                        P.DISCHARGE_P2_END,
                        P.DISCHARGE_P3_START,
                        P.DISCHARGE_P3_END
                    ]
            } 

            await sendCommand({
                cmd: 'local',
                act: '1',
                tid: '10001',
                data: dataKeys.map(k => ({ k }))
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
                    const names    = ['undefined', 'Self-Consumption', 'Backup', 'User Defined', 'Off-Grid'];
                    const badges   = ['badge-green','badge-green', 'badge-blue', 'badge-purple', 'badge-orange'];

                    // Monitor tab badge
                    const el = document.getElementById('activeWorkMode');
                    if (el) {
                        el.textContent = names[idx] ?? `Mode ${idx}`;
                        el.className   = `badge ${badges[idx] ?? 'badge-blue'}`;
                    }

                    // Config tab "Active" pill — mark only the matching button
                    const activeBtn = modeKey ? document.querySelector(`.mode-btn[data-mode="${modeKey}"]`) : null;
                    if (!activeBtn?.classList.contains('device-active')) {
                        document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('device-active'));
                        activeBtn?.classList.add('device-active');
                        if (modeKey) switchConfigMode(modeKey);
                    }
                    return;
                }

                document.querySelectorAll(`[data-param="${k}"]`).forEach(input => {
                    if (input.type === 'time') {
                        const t = secondsToTime(parseInt(v) || 0);
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
                    const cardMap  = { [P.CHARGE_P2_START]:'card-p2', [P.CHARGE_P3_START]:'card-p3', [P.DISCHARGE_P1_START]:'card-p4', [P.DISCHARGE_P2_START]:'card-p5', [P.DISCHARGE_P3_START]:'card-p6' };
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
        function timeToSeconds(timeStr) {
            timeToMinutes(timeStr) * 60
        }

        async function applyModeConfig(modeKey, btn) {
            if (!device || !device.gatt.connected) {
                log('❌ Not connected', 'error');
                return;
            }
            setButtonState(btn, 'loading');

            const section  = document.getElementById(`config-${modeKey}`);

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
                else if (el.type === 'time') v = timeToSeconds(el.value);
                else v = parseInt(el.value) || 0;
                pairs.push({ k, v });
            });
            
            const modes = ['undefined', 'selfconsumption', 'backup', 'userdefined', 'offgrid'];
            let modeNum = modes.indexOf(modeStr);
            const k = P.WORK_MODE;
            pairs.push({ k, modeNum} );
            const paramsOk = await writeParameterBatch(pairs);
            const ok = modeOk && paramsOk;
            
            setButtonState(btn, ok ? 'success' : 'error');
            if (ok) {
                log(`✅ ${modeNames[modeKey]} configuration applied`, 'success');
                await readConfigParams(modeKey);
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
            if (tabName === 'energy') {
                updateEnergyFlow();
            }
        }

        // ── Charts ────────────────────────────────────────

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

            // Power Overview Chart — Battery, PV and Grid on one graph
            const powerOverviewCanvas = document.getElementById('powerOverviewChart');
            if (!powerOverviewCanvas) {
                log('⚠️ powerOverviewChart canvas not found — Power Overview chart disabled', 'error');
            }
            powerOverviewChart = powerOverviewCanvas ? new Chart(powerOverviewCanvas, {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Battery Power (W)',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: '#10b98115',
                        tension: 0.3,
                        fill: false
                    }, {
                        label: 'PV Power (W)',
                        data: [],
                        borderColor: '#f59e0b',
                        backgroundColor: '#f59e0b15',
                        tension: 0.3,
                        fill: false
                    }, {
                        label: 'Active Power (W)',
                        data: [],
                        borderColor: '#8b5cf6',
                        backgroundColor: '#8b5cf615',
                        tension: 0.3,
                        fill: false
                    }, {
                        label: 'Grid Power (W)',
                        data: [],
                        borderColor: '#000000',
                        backgroundColor: '#8b5cf615',
                        tension: 0.3,
                        fill: false
                    }]
                }
            }) : null;

            // Battery Chart — SOC only
            batteryChart = new Chart(document.getElementById('batteryChart'), {
                ...chartConfig,
                data: {
                    labels: [],
                    datasets: [{
                        label: 'SOC (%)',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: '#10b98120',
                        tension: 0.3,
                        fill: true
                    }]
                },
                options: {
                    ...chartConfig.options,
                    scales: {
                        x: { display: true },
                        y: { display: true, min: 0, max: 100, ticks: { callback: v => v + '%' } }
                    }
                }
            });
        }

        function updateCharts() {
            if (!batteryChart || !powerOverviewChart || typeof Chart === 'undefined') return;

            const labels = historicalData.timestamps.map(t => t.toLocaleTimeString());

            // Power Overview
            powerOverviewChart.data.labels = labels;
            powerOverviewChart.data.datasets[0].data = historicalData.power;
            powerOverviewChart.data.datasets[1].data = historicalData.pvPower;
            powerOverviewChart.data.datasets[2].data = historicalData.activePower;
            powerOverviewChart.data.datasets[3].data = historicalData.currentLoad;
            powerOverviewChart.update('none');

            // Battery Chart — normalise SOC: P071 is decimal 0.0–1.0
            batteryChart.data.labels = labels;
            batteryChart.data.datasets[0].data = historicalData.soc.map(v => v > 1 ? v : v * 100);
            batteryChart.update('none');
        }

        // ─── Energy Flow Diagram ──────────────────────────────────────────────

        function efSetText(id, val) {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        }

        function efActivateFlow(fwdId, revId, active, watts, reverse) {
            const fwd = document.getElementById(fwdId);
            const rev = revId ? document.getElementById(revId) : null;
            if (!fwd) return;

            if (!active) {
                fwd.style.display = 'none';
                if (rev) rev.style.display = 'none';
                return;
            }

            // Speed: 2s @ 500W → 0.35s @ 5000W
            const dur = (Math.max(0.35, 2.0 / Math.max(0.1, watts / 500))).toFixed(2) + 's';

            if (reverse) {
                fwd.style.display = 'none';
                if (rev) {
                    rev.style.display = '';
                    rev.querySelectorAll('.ef-dot').forEach(c => c.style.animationDuration = dur);
                }
            } else {
                if (rev) rev.style.display = 'none';
                fwd.style.display = '';
                fwd.querySelectorAll('.ef-dot').forEach(c => c.style.animationDuration = dur);
            }
        }

        function efSetGlow(id, active, color) {
            const el = document.getElementById(id);
            if (!el) return;
            el.classList.toggle('ef-active', active);
            if (active && color) el.setAttribute('fill', color);
        }

        function efSetTrack(id, active, stroke, glowColor) {
            const el = document.getElementById(id);
            if (!el) return;
            el.style.display = active ? '' : 'none';
            if (active) {
                el.style.stroke = stroke;
                el.style.filter = `drop-shadow(0 0 5px ${glowColor})`;
            }
        }

        function updateEnergyFlow() {
            const pvW  = parseFloat(document.getElementById('pvPower')?.textContent)    || 0;
            const battW = parseFloat(document.getElementById('power')?.textContent)      || 0;

            // P055 (activePower) = house load (total consumption). Always >= 0. Unit: W.
            const homeW = parseFloat(document.getElementById('activePower')?.textContent) || 0;

            // P644 (currentLoad) = grid import/export. Positive = importing, negative = exporting.
            // Unit unconfirmed — assumed kW based on Monitor tab label; convert to W.
            const gridW = parseFloat(document.getElementById('currentLoad')?.textContent) || 0;

            // P071 (BATTERY_SOC): decimal 0.0–1.0 or integer 0–100.
            // Guard: ≤1 → decimal, multiply by 100.
            const socRaw = parseFloat(document.getElementById('soc')?.textContent) || 0;
            const socPct = socRaw > 1 ? socRaw : socRaw * 100;

            // Battery sign convention (confirmed by user):
            //   negative battW → charging  (energy flows hub → battery)
            //   positive battW → discharging (energy flows battery → hub)
            const battCharging    = battW < -50;
            const battDischarging = battW >  50;
            const battColor = battCharging ? '#34d399' : battDischarging ? '#fb923c' : '#6b7280';

            // ── Node values ──────────────────────────────────────────────────
            efSetText('ef-solar-power', pvW > 0 ? pvW.toFixed(0) + ' W' : '--');

            const battEl = document.getElementById('ef-batt-power');
            if (battEl) {
                battEl.textContent = Math.abs(battW) > 50 ? Math.abs(battW).toFixed(0) + ' W' : '--';
                battEl.setAttribute('fill', battColor);
            }

            efSetText('ef-batt-sub',
                socPct > 0 ? Math.round(socPct) + '% · Battery' : '-- · Battery');

            efSetText('ef-house-load', homeW > 0 ? homeW.toFixed(0) + ' W' : '--');

            efSetText('ef-grid-power',
                Math.abs(gridW) > 5
                    ? (gridW > 0 ? '+' : '') + gridW.toFixed(0) + ' W'
                    : '0 W');

            // ── Battery SOC fill bar (max width = 30px) ──────────────────────
            const fillEl = document.getElementById('ef-batt-fill');
            if (fillEl) {
                const w = Math.round(Math.max(0, Math.min(30, (socPct / 100) * 30)));
                fillEl.setAttribute('width', w);
                fillEl.setAttribute('fill',
                    socPct > 50 ? '#34d399' : socPct > 20 ? '#fbbf24' : '#f87171');
            }

            // ── Active track glows ────────────────────────────────────────────
            const battActive = battCharging || battDischarging;
            efSetTrack('tg-solar', pvW   > 10,            '#f59e0b', '#f59e0b');
            efSetTrack('tg-batt',  battActive,             battCharging ? '#10b981' : '#f97316',
                                                           battCharging ? '#10b981' : '#f97316');
            efSetTrack('tg-grid',  Math.abs(gridW) > 10,  '#8b5cf6', '#8b5cf6');
            efSetTrack('tg-home',  homeW > 50,             '#3b82f6', '#3b82f6');

            // ── Node glows ────────────────────────────────────────────────────
            efSetGlow('glow-solar', pvW  > 10,            '#f59e0b');
            efSetGlow('glow-batt',  battActive,            battCharging ? '#10b981' : '#f97316');
            efSetGlow('glow-grid',  Math.abs(gridW) > 10, '#8b5cf6');
            efSetGlow('glow-home',  homeW > 50,            '#3b82f6');

            // ── Flow dot animations ───────────────────────────────────────────
            // Solar: always hub-bound
            efActivateFlow('flow-solar-fwd', null,           pvW > 10,           pvW,              false);

            // Battery: negative = charging (rev: hub→battery), positive = discharging (fwd: battery→hub)
            efActivateFlow('flow-batt-fwd', 'flow-batt-rev', battActive, Math.abs(battW), battCharging);

            // Grid: positive = importing (fwd: grid→hub), negative = exporting (rev: hub→grid)
            efActivateFlow('flow-grid-fwd', 'flow-grid-rev', Math.abs(gridW) > 10, Math.abs(gridW), gridW < 0);

            // Home: always hub-bound
            efActivateFlow('flow-home-fwd', null,            homeW > 50,         homeW,            false);
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
