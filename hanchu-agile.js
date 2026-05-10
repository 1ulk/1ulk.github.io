        // Octopus Agile integration — price fetching and charge/discharge schedule optimisation.
        // Depends on globals from other modules: P, device, writeParameterBatch, setButtonState, log.

        const AGILE_REGIONS = [
            { code: 'A', name: 'Eastern England' },
            { code: 'B', name: 'East Midlands' },
            { code: 'C', name: 'London' },
            { code: 'D', name: 'North Wales & Merseyside' },
            { code: 'E', name: 'West Midlands' },
            { code: 'F', name: 'North East England' },
            { code: 'G', name: 'North West England' },
            { code: 'H', name: 'South England' },
            { code: 'J', name: 'South East England' },
            { code: 'K', name: 'South Wales' },
            { code: 'L', name: 'South West England' },
            { code: 'M', name: 'Yorkshire' },
            { code: 'N', name: 'South Scotland' },
            { code: 'P', name: 'North Scotland' },
        ];

        // ── API ───────────────────────────────────────────────────────────────

        async function agileGetProductCode() {
            const resp = await fetch('https://api.octopus.energy/v1/products/?is_variable=true&brand=OCTOPUS_ENERGY&page_size=100');
            if (!resp.ok) throw new Error(`Octopus products API returned ${resp.status}`);
            const data = await resp.json();
            // Find current (non-prepay) Agile product; sort by code desc to get the newest
            const products = data.results
                .filter(p => /^AGILE-/.test(p.code) && !p.is_prepay)
                .sort((a, b) => b.code.localeCompare(a.code));
            if (!products.length) throw new Error('No Agile product found in Octopus API');
            return products[0].code;
        }

        async function agileFetchPrices(region) {
            const code = await agileGetProductCode();
            const tariff = `E-1R-${code}-${region}`;

            // Fetch from now to 48 h ahead, rounded to last 30-min boundary
            const from = new Date();
            from.setMinutes(from.getMinutes() >= 30 ? 30 : 0, 0, 0);
            const to = new Date(from.getTime() + 48 * 3600 * 1000);

            const url = `https://api.octopus.energy/v1/products/${code}/electricity-tariffs/${tariff}/standard-unit-rates/` +
                `?period_from=${from.toISOString()}&period_to=${to.toISOString()}&page_size=100`;

            const resp = await fetch(url);
            if (!resp.ok) throw new Error(`Octopus rates API returned ${resp.status} — check your region`);
            const data = await resp.json();
            if (!data.results?.length) throw new Error("No price slots returned — tomorrow's prices may not be published yet (usually available after 4 pm)");

            return data.results
                .map(r => ({ from: new Date(r.valid_from), to: new Date(r.valid_to), pence: r.value_inc_vat }))
                .sort((a, b) => a.from - b.from);
        }

        // ── Schedule computation ──────────────────────────────────────────────

        function agileComputeWindows(slots, hours, cheapest) {
            const n = Math.max(1, Math.round(hours * 2));
            const ranked = [...slots].sort((a, b) => cheapest ? a.pence - b.pence : b.pence - a.pence);
            const selected = new Set(ranked.slice(0, n).map(s => s.from.getTime()));
            return agileMergeSlots(slots.filter(s => selected.has(s.from.getTime())));
        }

        function agileMergeSlots(slots) {
            if (!slots.length) return [];
            const sorted = [...slots].sort((a, b) => a.from - b.from);
            const blocks = [];
            let cur = { start: sorted[0].from, end: sorted[0].to };
            for (let i = 1; i < sorted.length; i++) {
                if (sorted[i].from.getTime() === cur.end.getTime()) {
                    cur.end = sorted[i].to;
                } else {
                    blocks.push(cur);
                    cur = { start: sorted[i].from, end: sorted[i].to };
                }
            }
            blocks.push(cur);
            return blocks.slice(0, 3); // inverter supports max 3 periods
        }

        function agileBlockToSeconds(block) {
            const toSec = d => d.getHours() * 3600 + d.getMinutes() * 60;
            return { start: toSec(block.start), end: toSec(block.end) };
        }

        // ── UI state ─────────────────────────────────────────────────────────

        let _agileChart = null;
        let _agileChargeBlocks = [];
        let _agileDischargeBlocks = [];

        function initAgileTab() {
            const sel = document.getElementById('agileRegion');
            const saved = localStorage.getItem('agileRegion') || 'C';
            AGILE_REGIONS.forEach(r => {
                const opt = document.createElement('option');
                opt.value = r.code;
                opt.textContent = `${r.name} (${r.code})`;
                if (r.code === saved) opt.selected = true;
                sel.appendChild(opt);
            });
            sel.addEventListener('change', () => localStorage.setItem('agileRegion', sel.value));
        }

        // ── UI handlers ───────────────────────────────────────────────────────

        async function fetchAndSuggestAgile(btn) {
            const region      = document.getElementById('agileRegion').value;
            const chargeHours = parseFloat(document.getElementById('agileChargeHours').value);
            const dischHours  = parseFloat(document.getElementById('agileDischargeHours').value);

            setButtonState(btn, 'loading');
            try {
                const slots = await agileFetchPrices(region);
                _agileChargeBlocks    = agileComputeWindows(slots, chargeHours, true);
                _agileDischargeBlocks = agileComputeWindows(slots, dischHours, false);

                agileRenderChart(slots, _agileChargeBlocks, _agileDischargeBlocks);
                agileRenderSummary(slots, _agileChargeBlocks, _agileDischargeBlocks);
                document.getElementById('agileApplyBtn').style.display = '';
                setButtonState(btn, 'success');
            } catch (err) {
                log(`❌ Agile: ${err.message}`, 'error');
                setButtonState(btn, 'error');
            }
        }

        async function applyAgileSchedule(btn) {
            if (!device?.gatt?.connected) { log('❌ Not connected', 'error'); return; }
            if (!_agileChargeBlocks.length) { log('❌ Fetch a schedule first', 'error'); return; }

            setButtonState(btn, 'loading');

            const chargePeriods = [
                { start: P.CHARGE_P1_START, end: P.CHARGE_P1_END },
                { start: P.CHARGE_P2_START, end: P.CHARGE_P2_END },
                { start: P.CHARGE_P3_START, end: P.CHARGE_P3_END },
            ];
            const dischargePeriods = [
                { start: P.DISCHARGE_P1_START, end: P.DISCHARGE_P1_END },
                { start: P.DISCHARGE_P2_START, end: P.DISCHARGE_P2_END },
                { start: P.DISCHARGE_P3_START, end: P.DISCHARGE_P3_END },
            ];

            const pairs = [];
            chargePeriods.forEach((p, i) => {
                const { start, end } = _agileChargeBlocks[i] ? agileBlockToSeconds(_agileChargeBlocks[i]) : { start: 0, end: 0 };
                pairs.push({ k: p.start, v: start }, { k: p.end, v: end });
            });
            dischargePeriods.forEach((p, i) => {
                const { start, end } = _agileDischargeBlocks[i] ? agileBlockToSeconds(_agileDischargeBlocks[i]) : { start: 0, end: 0 };
                pairs.push({ k: p.start, v: start }, { k: p.end, v: end });
            });
            pairs.push({ k: P.WORK_MODE, v: 3 }); // switch to User Defined

            const ok = await writeParameterBatch(pairs);
            setButtonState(btn, ok ? 'success' : 'error');
            if (ok) log('✅ Agile schedule applied — inverter set to User Defined mode', 'success');
        }

        // ── Rendering ─────────────────────────────────────────────────────────

        function agileRenderChart(slots, chargeBlocks, dischargeBlocks) {
            const inBlock = (date, blocks) => blocks.some(b => date >= b.start && date < b.end);

            const labels = slots.map(s =>
                s.from.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
            );
            const colors = slots.map(s => {
                if (inBlock(s.from, chargeBlocks))    return 'rgba(16,185,129,0.85)';
                if (inBlock(s.from, dischargeBlocks)) return 'rgba(239,68,68,0.85)';
                if (s.pence < 0)                      return 'rgba(59,130,246,0.85)';
                return 'rgba(156,163,175,0.55)';
            });

            const ctx = document.getElementById('agileChartCanvas').getContext('2d');
            if (_agileChart) _agileChart.destroy();
            _agileChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels,
                    datasets: [{
                        data: slots.map(s => s.pence),
                        backgroundColor: colors,
                        borderWidth: 0,
                    }],
                },
                options: {
                    plugins: {
                        legend: { display: false },
                        tooltip: { callbacks: { label: c => `${c.parsed.y.toFixed(1)}p/kWh` } },
                    },
                    scales: {
                        x: { ticks: { maxRotation: 45, autoSkip: true, maxTicksLimit: 16 } },
                        y: { title: { display: true, text: 'p/kWh' } },
                    },
                    animation: false,
                },
            });
            document.getElementById('agileChartWrap').style.display = '';
        }

        function agileRenderSummary(slots, chargeBlocks, dischargeBlocks) {
            const pad  = n => String(n).padStart(2, '0');
            const fmtT = d => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
            const fmtBlock = b => `${fmtT(b.start)}–${fmtT(b.end)}`;

            const avgPence = blocks => {
                let sum = 0, n = 0;
                slots.forEach(s => {
                    if (blocks.some(b => s.from >= b.start && s.from < b.end)) { sum += s.pence; n++; }
                });
                return n ? (sum / n).toFixed(1) : '—';
            };

            const periodRows = (blocks, label, cls) => blocks.length
                ? blocks.map((b, i) => `
                    <div class="agile-period ${cls}">
                        <span>${label} ${i + 1}</span><span>${fmtBlock(b)}</span>
                    </div>`).join('')
                : `<div class="agile-period agile-period-none"><span>${label}</span><span>none</span></div>`;

            document.getElementById('agileSummary').innerHTML = `
                <div class="agile-summary-group">
                    <div class="agile-summary-label">Charge  <small>avg ${avgPence(chargeBlocks)}p/kWh</small></div>
                    ${periodRows(chargeBlocks, 'Charge', 'agile-period-charge')}
                </div>
                <div class="agile-summary-group">
                    <div class="agile-summary-label">Discharge  <small>avg ${avgPence(dischargeBlocks)}p/kWh</small></div>
                    ${periodRows(dischargeBlocks, 'Discharge', 'agile-period-discharge')}
                </div>`;
            document.getElementById('agileSummary').style.display = '';
        }
