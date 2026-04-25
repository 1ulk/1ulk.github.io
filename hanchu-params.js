// hanchu-params.js
// Central registry of all known BLE parameter codes used in the Hanchu protocol.
//
// PARAMS  — full metadata for each code (name, description, unit, notes).
//           Use this to build UI labels, tooltips, or export headers.
//
// P       — named constants used in hanchu-controller.js instead of raw string literals.
//           Only codes actively referenced in code appear here.

// ─────────────────────────────────────────────────────────────────────────────
// Metadata registry
// ─────────────────────────────────────────────────────────────────────────────
const PARAMS = {

    // ═══════════════════════════════════════════════════════════════════════════
    // B-CODES — BMS / Battery module
    // ═══════════════════════════════════════════════════════════════════════════

    // Identity
    B002: { name: 'Battery Serial Number',        description: 'Unique serial number of the battery module (snActCode)' },
    B005: { name: 'Battery Brand',                description: 'Battery manufacturer brand name (brandCode)' },
    B145: { name: 'Battery Hardware Version',     description: 'Hardware revision string of the battery pack (hardwareActCode)' },
    B146: { name: 'Battery Model',                description: 'Battery model name, e.g. "Home-ESS-LV-9.4K" (modelActCode)' },
    B148: { name: 'Battery Firmware Version',     description: 'Firmware version of the battery pack (versionActCode)' },

    // Real-time measurements
    B034: { name: 'BMS State of Charge',          description: 'Battery state of charge reported by BMS as integer percent',                unit: '%' },
    B035: { name: 'Battery Pack Voltage',         description: 'Total battery pack voltage (V)',                                            unit: 'V' },
    B038: { name: 'Environmental Temperature',    description: 'Ambient/environmental temperature measured by BMS',                         unit: '°C' },
    B039: { name: 'Battery Temperature',          description: 'Internal battery cell temperature measured by BMS',                         unit: '°C' },
    B040: { name: 'PCBA Temperature',             description: 'Temperature of the battery management PCB assembly',                        unit: '°C' },
    B043: { name: 'Battery Current',              description: 'Battery charge/discharge current — positive = charging, negative = discharging', unit: 'A' },

    // Protocol / comms settings
    B153: { name: '485A Protocol',                description: 'RS-485 port A protocol selection (1 = HANCHUESS)' },
    B157: { name: 'CAN2 Protocol',               description: 'CAN2 bus protocol selection (1 = HANCHU)' },

    // ═══════════════════════════════════════════════════════════════════════════
    // L-CODES — Local / DTU / configuration
    // ═══════════════════════════════════════════════════════════════════════════

    // Work mode & scheduling
    L005: { name: 'Charge Period 1 Start',        description: 'Charge time period 1 start — minutes from midnight (t1_ch_start)' },
    L006: { name: 'Charge Period 1 End',          description: 'Charge time period 1 end — minutes from midnight (t1_ch_end)' },
    L007: { name: 'Charge Period 2 Start',        description: 'Charge time period 2 start — minutes from midnight (t2_ch_start)' },
    L008: { name: 'Charge Period 2 End',          description: 'Charge time period 2 end — minutes from midnight (t2_ch_end)' },
    L009: { name: 'Charge Period 3 Start',        description: 'Charge time period 3 start — minutes from midnight (t3_ch_start); 0 = disabled' },
    L010: { name: 'Charge Period 3 End',          description: 'Charge time period 3 end — minutes from midnight (t3_ch_end); 0 = disabled' },
    L011: { name: 'Discharge Period 1 Start',     description: 'Discharge time period 1 start — minutes from midnight (t4_ch_start); 0 = disabled' },
    L012: { name: 'Discharge Period 1 End',       description: 'Discharge time period 1 end — minutes from midnight (t4_ch_end); 0 = disabled' },
    L013: { name: 'Discharge Period 2 Start',     description: 'Discharge time period 2 start — minutes from midnight (t5_ch_start); 0 = disabled' },
    L014: { name: 'Discharge Period 2 End',       description: 'Discharge time period 2 end — minutes from midnight (t5_ch_end); 0 = disabled' },
    L015: { name: 'Discharge Period 3 Start',     description: 'Discharge time period 3 start — minutes from midnight (t6_ch_start); 0 = disabled' },
    L016: { name: 'Discharge Period 3 End',       description: 'Discharge time period 3 end — minutes from midnight (t6_ch_end); 0 = disabled' },
    L017: { name: 'Charge Power Limit',           description: 'Maximum battery charge power (chg_limit)',                                  unit: 'W' },
    L018: { name: 'Discharge Power Limit',        description: 'Maximum battery discharge power (dischg_limit)',                            unit: 'W' },
    L019: { name: 'Work Mode (L-code)',           description: 'Operating mode: 1 = Self-Consumption, 2 = Backup, 3 = User-Defined, 4 = Off-Grid (mirrors P651)' },

    // Time & locale
    L020: { name: 'Timezone',                     description: 'IANA timezone code for the DTU, e.g. "Europe/London" (timeZoneActCode)' },
    L021: { name: 'Clear WiFi Password',          description: 'Write trigger to clear stored WiFi credentials (0 = idle, 1 = clear)' },
    L094: { name: 'Unix Timestamp',               description: 'Current Unix epoch timestamp set on the DTU (timeStampActCode)',            unit: 's' },
    L096: { name: 'Timezone Offset',              description: 'UTC offset in hours (timeZoneOffsetActCode)' },

    // DTU / logger identity
    L023: { name: 'DTU Firmware Version',         description: 'Software version of the data logger / DTU (dtuVersionActCode / actLoggerSoftVersion)' },
    L025: { name: 'DTU Brand',                    description: 'Brand name of the data logger unit (dtuBrandCode), e.g. "HANCHU"' },
    L026: { name: 'DTU Model',                    description: 'Model identifier of the data logger — "INV-Logger" for inverter, "BAT-Logger" for battery (dtuModelActCode)' },

    // Grid & meter settings
    L034: { name: 'Meter Type',                   description: 'CT/meter type code — 0 = no meter, 3 = specific supported meter (meterTypeCode)' },

    // System state flags
    L041: { name: 'No Load Mode',                 description: 'No-load (NL) mode flag — 0 = normal, 1 = no-load mode active (isNLModeCode)' },
    L052: { name: 'CLS State',                    description: 'Cloud link / connection state flag (clsStateCode)' },
    L074: { name: 'Max SOC Limit',                description: 'Upper SOC limit for grid-to-battery charging — battery will not charge above this level', unit: '%' },
    L085: { name: 'Outdoor Controller Linkage',   description: 'External/outdoor controller linkage — 0 = off, 10 = on' },
    L100: { name: 'WiFi Status',                  description: 'WiFi connectivity status — 1 = connected, 0 = disconnected (wifi_status)' },
    L108: { name: 'Intelligent Battery Preheating', description: 'Automated battery preheating — 0 = off, 1 = on' },
    L114: { name: 'Manual Battery Preheating',    description: 'Manually triggered battery preheating — 0 = off, 1 = on' },

    // Device name substrings (used for type detection, not BLE parameters)
    L101: { name: 'Device Type ID: Battery',      description: 'Device name substring that identifies a Battery unit (used for BLE device detection)' },
    L110: { name: 'Device Type ID: Inverter',     description: 'Device name substring that identifies an Inverter unit (used for BLE device detection)' },

    // ═══════════════════════════════════════════════════════════════════════════
    // P-CODES — Power / inverter
    // ═══════════════════════════════════════════════════════════════════════════

    // Device identity
    P000: { name: 'Phase Mode',                   description: 'AC phase configuration — 0 = single phase, 3 = three phase (actIsThreeMode)' },
    P002: { name: 'Inverter Serial Number',       description: 'Unique serial number of the inverter (snActCode)' },
    P003: { name: 'Inverter Model',               description: 'Device model identifier, e.g. "HYB-5K" (devModelCode)' },
    P005: { name: 'Inverter Power Limit',         description: 'Rated power limit of the inverter',                                         unit: 'W' },
    P006: { name: 'Inverter Firmware Version',    description: 'Main inverter software version (actInvSoftVersion / devVersionCode)' },
    P007: { name: 'Safety Firmware Version',      description: 'Safety subsystem firmware version of the inverter (actInvSafetyVersion)' },
    P008: { name: 'Inverter Brand',               description: 'Brand name of the inverter, e.g. "HANCHU" (devBrandCode)' },
    P139: { name: 'ARM Firmware Version',         description: 'ARM processor firmware version of the inverter (actInvArmVersion)' },

    // PV (Solar) real-time
    P024: { name: 'PV String 1 Voltage',          description: 'Voltage of PV input string 1',                                             unit: 'V' },
    P025: { name: 'PV String 1 Current',          description: 'Current of PV input string 1',                                             unit: 'A' },
    P026: { name: 'PV String 2 Voltage',          description: 'Voltage of PV input string 2',                                             unit: 'V' },
    P027: { name: 'PV String 2 Current',          description: 'Current of PV input string 2',                                             unit: 'A' },
    P060: { name: 'Total PV Power',               description: 'Combined real-time output power from all PV strings',                       unit: 'W' },
    P061: { name: 'PV Energy Today',              description: 'Solar energy generated today',                                              unit: 'kWh' },
    P062: { name: 'PV Energy Accumulated',        description: 'Total lifetime solar energy generated',                                     unit: 'kWh' },

    // Grid real-time
    P044: { name: 'Grid Voltage L1',              description: 'AC grid line 1 voltage',                                                    unit: 'V' },
    P045: { name: 'Grid Current L1',              description: 'AC grid line 1 current',                                                    unit: 'A' },
    P046: { name: 'Grid Parameter (P046)',        description: 'Grid-related parameter — exact meaning unconfirmed (seen in device logs)' },
    P048: { name: 'Grid Parameter (P048)',        description: 'Grid-related parameter — exact meaning unconfirmed (seen in device logs)' },
    P053: { name: 'Grid Frequency',               description: 'AC grid frequency',                                                         unit: 'Hz' },
    P055: { name: 'Grid Active Power',            description: 'Net active power at grid connection point — positive = import from grid',   unit: 'W' },
    P056: { name: 'Grid Reactive Power',          description: 'Reactive power at grid connection',                                         unit: 'Var' },
    P057: { name: 'Grid Power Factor',            description: 'Power factor at the grid connection point (0.00–1.00)' },

    // Battery status (inverter-side readings)
    P063: { name: 'Battery Comms Status',         description: 'Battery communication link status — 0 = disconnected, 1 = connected' },
    P064: { name: 'Battery State',                description: 'Battery operational state — 0 = disconnected, 1 = normal, 2 = charging, 3 = discharging (batteryStateCode)' },
    P067: { name: 'Battery Voltage (alt)',        description: 'Battery voltage as seen by the inverter — alternative to B035',             unit: 'V' },
    P068: { name: 'Battery Current (alt)',        description: 'Battery current as seen by the inverter — alternative to B043 (batteryCurrentCode)', unit: 'A' },
    P069: { name: 'Battery Power',                description: 'Battery charge/discharge power — positive = charging',                      unit: 'W' },
    P070: { name: 'Battery Temperature',          description: 'Battery temperature as reported by the inverter',                           unit: '°C' },
    P071: { name: 'Battery SOC (decimal)',        description: 'Battery state of charge in decimal format — e.g. 0.67 = 67% (currentSocCode)', unit: '%' },
    P075: { name: 'Battery Charge Today',         description: 'Energy charged into battery today',                                         unit: 'kWh' },
    P076: { name: 'Battery Discharge Today',      description: 'Energy discharged from battery today',                                      unit: 'kWh' },
    P088: { name: 'Battery Capacity',             description: 'Rated battery capacity',                                                    unit: 'Ah' },

    // EPS (Emergency Power Supply)
    P079: { name: 'EPS Voltage',                  description: 'EPS output voltage during grid outage',                                     unit: 'V' },
    P080: { name: 'EPS Current',                  description: 'EPS output current during grid outage',                                     unit: 'A' },
    P081: { name: 'EPS Frequency',                description: 'EPS output frequency during grid outage',                                   unit: 'Hz' },
    P082: { name: 'EPS Active Power',             description: 'EPS active power output during grid outage',                                unit: 'W' },
    P083: { name: 'EPS Reactive Power',           description: 'EPS reactive power output during grid outage',                              unit: 'Var' },
    P084: { name: 'EPS Energy Today',             description: 'EPS energy delivered today',                                                unit: 'kWh' },
    P085: { name: 'EPS Energy Accumulated',       description: 'Total lifetime EPS energy delivered',                                       unit: 'kWh' },

    // Self-check / diagnostics
    P011: { name: 'Parameter P011',               description: 'Exact meaning unconfirmed (seen in device logs)' },
    P150: { name: 'Self-Check Start',             description: 'Trigger self-check routine — 0 = idle, 1 = start (startCheckCode)' },
    P151: { name: 'Self-Check Sequence Number',   description: 'Identifies the current check in the self-check sequence (checkNumberCode)' },
    P152: { name: 'Self-Check Status',            description: 'Self-check run state — 0 = idle, 1 = running, 2 = complete (checkStatusCode)' },
    P153: { name: 'Self-Check Result',            description: 'Self-check outcome — 0 = pass, 1 = fail (checkResultCode)' },
    P662: { name: 'Self-Check Enable Flag 1',     description: 'Enables self-check function group 1 — 0 = disabled, 1 = enabled (checkEnableCode1)' },
    P663: { name: 'Self-Check Enable Flag 2',     description: 'Enables self-check function group 2 — 0 = disabled, 1 = enabled (checkEnableCode2)' },

    // Meter & grid export settings
    P236: { name: 'Meter PV Enable',              description: 'Enable CT/meter PV measurement — 0 = off, 1 = on (byMeterPVCode)' },
    P245: { name: 'Meter PV Direction',           description: 'CT/meter PV energy direction — 0 = import, 1 = export (byMeterPVDirectionCode)' },
    P254: { name: 'EC Power Limit',               description: 'Economic control power limit',                                              unit: 'W' },
    P255: { name: 'Global EC Power Limit',        description: 'Global economic control power limit',                                       unit: 'W' },
    P359: { name: 'Grid 100% Input',              description: 'Grid normalisation reference for 100% input (g100_input)',                   unit: '%' },
    P360: { name: 'Grid 100% Output',             description: 'Grid normalisation reference for 100% output (g100_output)',                 unit: '%' },
    P363: { name: 'Comms Disconnect Timeout',     description: 'Timeout before treating a comms loss as a disconnection (commun_discon)',    unit: 's' },
    P364: { name: 'Anti-Islanding Type',          description: 'Anti-islanding protection algorithm selection (anti_type)' },
    P497: { name: 'Restrict Mode',                description: 'Restrict mode flag — limits certain inverter operations (restrictModeCode)' },
    P500: { name: 'Grid Relay / Power State',     description: 'Grid relay and inverter power state — 1 = ON, 0 = OFF' },
    P510: { name: 'Anti-Reverse',                 description: 'Anti-reverse current protection setting (anti_reverse)' },
    P511: { name: 'Battery Recovery',             description: 'Battery recovery mode trigger — 5 = off, 10 = on' },
    P652: { name: 'Grid Export Limit',            description: 'Maximum power that may be exported to the grid (togrid_limit)',             unit: 'W' },

    // Battery pack configuration
    P142: { name: 'Battery Pack Count',           description: 'Number of battery packs connected (float)' },
    P237: { name: 'Battery Pack Parameter',       description: 'Battery pack configuration parameter (float)' },
    P238: { name: 'Battery Pack Location',        description: 'Physical location/slot of the battery pack (bp_location)' },
    P239: { name: 'AC Couple Meter Type',         description: 'Meter type for AC-coupled side (bp_type)' },
    P240: { name: 'Reserved (P240)',              description: 'Reserved parameter — purpose unconfirmed' },
    P241: { name: 'Reserved (P241)',              description: 'Reserved parameter — purpose unconfirmed' },

    // Energy statistics (today)
    P638: { name: 'Grid Power Purchased Today',   description: 'Energy imported from the grid today',                                       unit: 'kWh' },
    P639: { name: 'Grid Power Sold Today',        description: 'Energy exported to the grid today',                                         unit: 'kWh' },

    // Control & mode configuration
    P647: { name: 'Charge-To SOC',               description: 'Upper SOC target — battery charges to this level then stops (chargeSocCode)', unit: '%' },
    P648: { name: 'Discharge-To SOC',            description: 'Lower SOC target — battery discharges to this level then stops (dischargeSocCode)', unit: '%' },
    P651: { name: 'Work Mode',                    description: 'Operating mode: 1 = Self-Consumption, 2 = Backup, 3 = User-Defined, 4 = Off-Grid (mirrors L019)' },
    P772: { name: 'Min SOC (Discharge Cutoff)',  description: 'Hard minimum SOC floor — battery will never discharge below this level',     unit: '%' },

    // Advanced / reserved parameters (seen in device logs)
    P498: { name: 'Reserved (P498)',              description: 'Reserved parameter — purpose unconfirmed' },
    P499: { name: 'Reserved (P499)',              description: 'Reserved parameter — float value, purpose unconfirmed' },
    P640: { name: 'Reserved (P640)',              description: 'Reserved parameter — purpose unconfirmed' },
    P641: { name: 'Reserved (P641)',              description: 'Reserved parameter — purpose unconfirmed' },
    P642: { name: 'Reserved (P642)',              description: 'Reserved parameter — float value, purpose unconfirmed' },
    P643: { name: 'Reserved (P643)',              description: 'Reserved parameter — float value, purpose unconfirmed' },
    P644: { name: 'Reserved (P644)',              description: 'Reserved parameter — float value, purpose unconfirmed' },
    P685: { name: 'Unknown (P685)',               description: 'Undocumented — seen in device logs' },
    P686: { name: 'Unknown (P686)',               description: 'Undocumented — seen in device logs' },
    P687: { name: 'Unknown (P687)',               description: 'Undocumented — seen in device logs' },
    P691: { name: 'Unknown (P691)',               description: 'Undocumented — seen in device logs' },
    P692: { name: 'Unknown (P692)',               description: 'Undocumented — seen in device logs' },
    P693: { name: 'Unknown (P693)',               description: 'Undocumented — seen in device logs' },

    // ═══════════════════════════════════════════════════════════════════════════
    // Legacy device codes (deprecated SNs from older firmware)
    // ═══════════════════════════════════════════════════════════════════════════
    R014: { name: 'SR Inverter Serial Number',    description: 'Legacy serial number for SR-series inverters (deprecated)' },
    T006: { name: 'TQ Inverter Serial Number',    description: 'Legacy serial number for TQ-series inverters (deprecated)' },
};

// ─────────────────────────────────────────────────────────────────────────────
// Named constants — use these throughout hanchu-controller.js
// ─────────────────────────────────────────────────────────────────────────────
const P = {

    // ── Battery module (BMS) ─────────────────────────────────────────────────
    BATTERY_SERIAL:             'B002',
    BMS_SOC:                    'B034',  // integer %, e.g. 67 — see also BATTERY_SOC (P071, decimal)
    BATTERY_TERMINAL_VOLTAGE:   'P067',
    BATTERY_CURRENT:            'P068',

    // ── Charge time periods ──────────────────────────────────────────────────
    CHARGE_P1_START:            'L005',
    CHARGE_P1_END:              'L006',
    CHARGE_P2_START:            'L007',
    CHARGE_P2_END:              'L008',
    CHARGE_P3_START:            'L009',
    CHARGE_P3_END:              'L010',

    // ── Discharge time periods ───────────────────────────────────────────────
    DISCHARGE_P1_START:         'L011',
    DISCHARGE_P1_END:           'L012',
    DISCHARGE_P2_START:         'L013',
    DISCHARGE_P2_END:           'L014',
    DISCHARGE_P3_START:         'L015',
    DISCHARGE_P3_END:           'L016',

    // ── Power limits & SOC thresholds ────────────────────────────────────────
    CHARGE_POWER_LIMIT:         'L017',
    DISCHARGE_POWER_LIMIT:      'L018',
    MAX_SOC_LIMIT:              'L074',

    // ── Device identity ──────────────────────────────────────────────────────
    DTU_FIRMWARE:               'L023',
    DEVICE_TYPE_BATTERY:        'L101',  // BLE device name substring
    DEVICE_TYPE_INVERTER:       'L110',  // BLE device name substring
    INVERTER_SERIAL:            'P002',
    INVERTER_FIRMWARE:          'P006',

    // ── PV strings ───────────────────────────────────────────────────────────
    PV1_VOLTAGE:                'P024',
    PV1_CURRENT:                'P025',
    PV2_VOLTAGE:                'P026',
    PV2_CURRENT:                'P027',

    // ── Grid ─────────────────────────────────────────────────────────────────
    GRID_VOLTAGE:               'P044',
    GRID_CURRENT:               'P045',
    GRID_FREQUENCY:             'P053',
    GRID_ACTIVE_POWER:          'P055',
    GRID_REACTIVE_POWER:        'P056',
    POWER_ON:                   'P500',
    GRID_PURCHASED_TODAY:       'P638',
    GRID_SOLD_TODAY:            'P639',

    // ── PV totals ────────────────────────────────────────────────────────────
    PV_POWER_TOTAL:             'P060',
    PV_ENERGY_TODAY:            'P061',
    PV_ENERGY_ACCUMULATED:      'P062',

    // ── Battery metrics (inverter-side) ──────────────────────────────────────
    BATTERY_POWER:              'P069',
    BATTERY_TEMPERATURE:        'P070',
    BATTERY_SOC:                'P071',  // decimal, e.g. 0.67 = 67% — see also BMS_SOC (B034, integer)
    BATTERY_CHARGE_TODAY:       'P075',
    BATTERY_DISCHARGE_TODAY:    'P076',

    // ── Control ──────────────────────────────────────────────────────────────
    CHARGE_TO_SOC:              'P647',
    DISCHARGE_TO_SOC:           'P648',
    WORK_MODE:                  'P651',  // 1=Self-Consumption 2=Backup 3=User-Defined 4=Off-Grid
    MIN_SOC_CUTOFF:             'P772',


    LOAD: 'P644',
    // ── Also referenced in code ──────────────────────────────────────────────
    BMS_FIRMWARE:               'L023',  // alias kept for backward compat — same as DTU_FIRMWARE
};
