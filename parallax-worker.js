// PARALLAX Web Worker — heavy processing off main thread
// Receives: { type, payload } messages
// Returns: { type, result } messages

// Import pako for decompression
importScripts('https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js');

function postLog(msg) {
  self.postMessage({ type: 'log', text: msg });
}

function postProgress(pct, label) {
  self.postMessage({ type: 'progress', pct, label });
}

// ── Minimal POSIX ustar tar parser ──
function parseTar(buffer) {
  const entries = {};
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let pos = 0;
  while (pos + 512 <= u8.length) {
    const nameRaw = readStr(u8, pos, 100);
    if (!nameRaw || nameRaw[0] === '\0') break;
    const sizeOct = readStr(u8, pos + 124, 12);
    const type    = u8[pos + 156];
    const prefix  = readStr(u8, pos + 345, 155);
    const size    = parseInt(sizeOct.trim() || '0', 8) || 0;
    const name    = (prefix ? prefix + '/' : '') + nameRaw;
    pos += 512;
    if (type === 48 || type === 0) {
      entries[name] = u8.slice(pos, pos + size);
    }
    pos += Math.ceil(size / 512) * 512;
  }
  return entries;
}

function readStr(u8, start, len) {
  let end = start;
  while (end < start + len && u8[end] !== 0) end++;
  return new TextDecoder('ascii', {fatal:false}).decode(u8.slice(start, end));
}

// ── Decompress + Parse Tar + Decode ──
async function decompressAndParse(fileBuffer) {
  const u8 = new Uint8Array(fileBuffer);
  const sizeMB = (u8.length / 1024 / 1024).toFixed(0);
  postLog(`[INFO] File loaded (${sizeMB} MB compressed)`);

  let rawBytes;

  if (u8[0] === 0x1f && u8[1] === 0x8b) {
    postLog('[INFO] Decompressing with pako streaming inflate...');
    const inflator = new pako.Inflate();
    const CHUNK = 2 * 1024 * 1024;
    for (let i = 0; i < u8.length; i += CHUNK) {
      const end = Math.min(i + CHUNK, u8.length);
      inflator.push(u8.subarray(i, end), end === u8.length);
      if (inflator.err) throw new Error('Inflate: ' + inflator.msg);
      if (i % (20 * 1024 * 1024) === 0 && i > 0) {
        postLog(`[INFO] Decompressing... ${(i / 1024 / 1024).toFixed(0)} MB processed`);
        postProgress(Math.round((i / u8.length) * 40), 'Decompressing...');
      }
    }
    rawBytes = inflator.result;
    postLog(`[INFO] Decompressed (${(rawBytes.length / 1024 / 1024).toFixed(0)} MB)`);
  } else {
    rawBytes = u8;
  }

  postLog('[INFO] Parsing tar...');
  postProgress(40, 'Parsing tar...');
  const tarEntries = parseTar(rawBytes);
  rawBytes = null; // free

  const entryNames = Object.keys(tarEntries);
  postLog(`[INFO] tar contains ${entryNames.length} entries`);

  const decoder = new TextDecoder('utf-8', {fatal: false});
  const tracev3Files = {};
  let pmuText = '';
  const dscBlobs = {};

  let processed = 0;
  for (const name of entryNames) {
    const base = name.split('/').pop();
    const data = tarEntries[name];

    if (base.endsWith('.tracev3')) {
      tracev3Files[base] = decoder.decode(data);
    }
    if (base === 'pmudiagnose.txt') {
      pmuText = decoder.decode(data);
    }
    if (name.includes('/dsc/') && /^[0-9A-Fa-f]{32}$/.test(base)) {
      dscBlobs[base] = data;
    }

    // Free tar entry after extraction
    tarEntries[name] = null;

    processed++;
    if (processed % 200 === 0) {
      postProgress(40 + Math.round((processed / entryNames.length) * 10), 'Extracting files...');
    }
  }

  return { tracev3Files, pmuText, dscBlobs };
}

// ── Scan tracev3 files for indicators ──
// This runs all the pattern matching that was blocking the main thread
function scanTracev3(tracev3Files, IOCS, pmuText) {
  postLog('[INFO] Scanning indicators...');
  postProgress(50, 'Scanning...');

  function countIn(text, pattern) {
    let c = 0, i = 0;
    while ((i = text.indexOf(pattern, i)) !== -1) { c++; i += pattern.length; }
    return c;
  }

  function regionAllZero(pmText, rnum) {
    const re = new RegExp(`region-${rnum}:([\\s\\S]*?)(?=\\tregion-|$)`);
    const m = pmText.match(re);
    if (!m) return null;
    const rows = [...m[1].matchAll(/0x[0-9a-f]+:\s*([\s0-9a-f]+)rc=/g)];
    return rows.length > 0 && rows.every(r => r[1].trim().split(/\s+/).every(v => v === '00'));
  }

  const result = {
    device_model: '', soc_id: '', ios_version: '', ios_build: '',
    tracev3_count: Object.keys(tracev3Files).length,
    indicators: [], apps_under_collection: [],
    ohf_nodes_found: [],
    persona_total: 0, persona_variant_total: 0,
    bearer_total: 0, carrier_mismatch: null,
    behavioral_triad_active: false, behavioral_triad_files: 0,
    c2_hit_counts: {}, ohf_files: [],
    rtbuddy_files: [], commcenter_files: [], launch_files: [],
    ifsample_files: [], seymour_files: [],
    dsc_blobs_found: 0, dsc_ghost_entries: [],
    dsc_non_apple_bundles: [], dsc_suspicious_paths: [],
    dsc_operator_uuids: [], dsc_embedded_domains: [],
    dsc_implant_blobs: [],
    dsc_hash_matches: [], dsc_symbol_hits: [], dsc_c2_ip_hits: [],
    dsc_bad_url_hits: [], dsc_uuid_crossrefs: [],
    verdict: '', simulated_reality: false, confirmed_count: 0
  };

  function addIndicator(layer, name, status, count, detail) {
    result.indicators.push({ layer, name, status, count, detail });
  }

  // Device identity
  const soc_map = {T8101:'A14 Bionic',T8110:'A15 Bionic',T8120:'A16 Bionic',
                   T8130:'A17 Pro',T8140:'A18',T8150:'A18 Pro'};

  // Single pass per file — collect all indicators at once
  const entries = Object.entries(tracev3Files);
  let dartTotal = 0, ispTotal = 0, cooccur = 0, l0files = [];
  let bearerTotal = 0, l1files = [], ipdpFiles = [], multihopFiles = [];
  let rtbuddyFiles = [], commcenterFiles = [];
  let overrideF = [], streamF = [], walFuture = false;
  let personaTotal = 0, personaVariantTotal = 0, l3aFiles = [], appsFound = new Set();
  let triadFiles = [];
  let cmFiles = [], orFiles = [], gwFiles = [], launchFiles = [];
  let ohfFiles = [], c2Hits = {}, kayleesF = [];
  const kayleesUUIDMap = {};
  const UUID_RE = /\b([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\b/g;
  let ifSampleFiles = [], seymourFiles = [];
  const harvestedUUIDs = new Set();

  const futureYear = new Date().getFullYear();
  const futureRe = new RegExp((futureYear + 1) + '|' + futureYear + '-(0[7-9]|1[0-2])');

  for (let fi = 0; fi < entries.length; fi++) {
    const [fname, text] = entries[fi];

    // Device identity (first match wins)
    for (const [pat, name] of Object.entries(soc_map)) {
      if (!result.soc_id && text.includes(pat)) result.soc_id = name;
    }
    if (!result.device_model) {
      const bm = text.match(/iPhone(\d+),(\d+)/);
      if (bm) result.device_model = `iPhone${bm[1]},${bm[2]}`;
    }
    if (!result.ios_version) {
      const vm = text.match(/\b(\d{2,3}\.\d+\.\d+)\b/);
      if (vm) result.ios_version = vm[1];
    }
    if (!result.ios_build) {
      const em = text.match(/\b([0-9]{2}[A-Z][0-9]{4,6})\b/);
      if (em) result.ios_build = em[1];
    }

    // L0 DART
    dartTotal += countIn(text, IOCS.dart_string);
    const ispIdx = [...text.matchAll(new RegExp(IOCS.isp_string, 'g'))].map(m => m.index);
    ispTotal += ispIdx.length;
    for (const idx of ispIdx) {
      if (text.slice(idx, idx + 220).includes(IOCS.dart_string)) {
        cooccur++;
        if (!l0files.includes(fname)) l0files.push(fname);
      }
    }

    // L1 Shadow bearer
    const bcnt = countIn(text, IOCS.shadow_bearer);
    bearerTotal += bcnt;
    if (bcnt) l1files.push(fname);
    if (text.includes('ipdp_ip0')) ipdpFiles.push(fname);
    if (text.includes('MultiHop')) multihopFiles.push(fname);
    if (text.includes(IOCS.rtbuddy_endpoint)) rtbuddyFiles.push(fname);
    if (text.includes(IOCS.commcenter_xpc)) commcenterFiles.push(fname);

    // L2 TCC
    if (text.includes(IOCS.tcc_override)) overrideF.push(fname);
    if (text.includes(IOCS.tcc_stream)) streamF.push(fname);
    if (futureRe.test(text)) walFuture = true;

    // L3a Persona
    const pcnt = countIn(text, IOCS.collection_persona) + countIn(text, IOCS.persona_alt);
    personaTotal += pcnt;
    personaVariantTotal += countIn(text, IOCS.persona_alt_variant);
    if (pcnt) {
      l3aFiles.push(fname);
      for (const appPat of IOCS.collection_apps) {
        const re = new RegExp(`${appPat.replace(/\./g, '\\.')}[\\s\\S]{0,120}${IOCS.collection_persona}`, 'g');
        if (re.test(text)) appsFound.add(appPat);
      }
    }
    if (IOCS.behavioral_triad.every(t => text.includes(t))) {
      triadFiles.push(fname);
    }

    // L3b Egress anchor
    if (text.includes(IOCS.ciphermld_pid) || text.includes(IOCS.ciphermld_bundle)) cmFiles.push(fname);
    if (text.includes(IOCS.or_maintainer)) orFiles.push(fname);
    if (text.includes(IOCS.gateway_o_uuid)) gwFiles.push(fname);
    if (text.includes(IOCS.launch_mechanism) && text.includes('networkserviceproxy')) {
      const idx = text.indexOf(IOCS.launch_mechanism);
      const ctx = text.slice(Math.max(0, idx - 300), idx + 300);
      if (ctx.includes('networkserviceproxy')) launchFiles.push(fname);
    }

    // L5 Egress
    if (text.includes('ObliviousHopFallback')) ohfFiles.push(fname);
    if (text.includes('kaylees')) {
      kayleesF.push(fname);
      const lines = text.split('\n').filter(l => l.includes('kaylees'));
      for (const ln of lines) {
        let m;
        UUID_RE.lastIndex = 0;
        while ((m = UUID_RE.exec(ln)) !== null) {
          const u = m[1].toUpperCase();
          if (!kayleesUUIDMap[u]) kayleesUUIDMap[u] = new Set();
          kayleesUUIDMap[u].add(fname);
        }
      }
    }
    for (const dom of IOCS.c2_domains) {
      if (text.includes(dom)) c2Hits[dom] = (c2Hits[dom] || 0) + 1;
    }

    // L6 Suppression (secondary)
    if (text.includes(IOCS.suppression_cache)) seymourFiles.push(fname);
    if (text.includes(IOCS.ifSample_pattern)) {
      const idx = text.indexOf(IOCS.ifSample_pattern);
      if (text.slice(idx, idx + 500).includes(IOCS.ifSample_zero)) {
        ifSampleFiles.push(fname);
      }
    }

    // UUID harvesting for L7 cross-reference
    const uuidLogRE = /\b([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}|[a-fA-F0-9]{32})\b/g;
    let um;
    while ((um = uuidLogRE.exec(text)) !== null) {
      harvestedUUIDs.add(um[1].toLowerCase().replace(/-/g, ''));
    }

    if (fi % 3 === 0) {
      postProgress(50 + Math.round((fi / entries.length) * 30), `Scanning file ${fi + 1}/${entries.length}...`);
    }
  }

  // ── Build indicators ──

  // L0
  addIndicator('L0', 'Hardware Attestation Bypass (DART/ISP)',
    cooccur >= 3 ? 'CONFIRMED' : cooccur >= 1 ? 'POSSIBLE' : 'NOT_DETECTED',
    cooccur, `DARTMappings ${dartTotal}x  ISP_FlushIn ${ispTotal}x  co-occurrences ${cooccur}`);

  // L1
  result.bearer_total = bearerTotal;
  result.rtbuddy_files = rtbuddyFiles;
  result.commcenter_files = commcenterFiles;
  const l1parts = [`${IOCS.shadow_bearer} bearer ${bearerTotal}x`];
  if (rtbuddyFiles.length) l1parts.push(`RTBuddyOSLogEndpoint in ${rtbuddyFiles.length} files`);
  if (commcenterFiles.length) l1parts.push(`CommCenter XPC in ${commcenterFiles.length} files`);
  if (ipdpFiles.length) l1parts.push(`ipdp_ip0 in ${ipdpFiles.length} files`);
  if (multihopFiles.length) l1parts.push(`MultiHop in ${multihopFiles.length} files`);
  const l1status = (rtbuddyFiles.length > 0 && bearerTotal > 0) ? 'CONFIRMED' :
    bearerTotal > 0 ? 'POSSIBLE' : 'NOT_DETECTED';
  addIndicator('L1', 'Shadow Bearer / Baseband / IPDP Egress', l1status, bearerTotal, l1parts.join(' \u00B7 '));

  // L2
  const l2parts = [];
  let l2status = 'NOT_DETECTED';
  if (overrideF.length) { l2parts.push(`TCCAccessGetOverride in ${overrideF.length} files`); l2status = 'CONFIRMED'; }
  if (streamF.length) { l2parts.push('privacy.accounting.stream.tcc injected'); l2status = 'CONFIRMED'; }
  if (walFuture) l2parts.push('WAL future-dated entries');
  addIndicator('L2', 'TCC Permission Staging', l2status, 0,
    l2parts.length ? l2parts.join(' \u00B7 ') : 'No TCC anomalies detected');

  // L3a
  result.persona_total = personaTotal;
  result.persona_variant_total = personaVariantTotal;
  result.apps_under_collection = [...appsFound].sort();
  result.behavioral_triad_active = triadFiles.length >= 3;
  result.behavioral_triad_files = triadFiles.length;
  const l3aParts = [`persona-primary ${personaTotal}x across ${l3aFiles.length} files`];
  if (personaVariantTotal > 0) l3aParts.push(`persona-settings ${personaVariantTotal}x`);
  l3aParts.push(`${appsFound.size} apps confirmed`);
  if (result.behavioral_triad_active) l3aParts.push(`behavioral profiling triad active in ${triadFiles.length} files`);
  addIndicator('L3a', 'Collection Anchor (Persona / RunningBoard)',
    personaTotal > 100 ? 'CONFIRMED' : personaTotal > 0 ? 'POSSIBLE' : 'NOT_DETECTED',
    personaTotal, l3aParts.join(' \u00B7 '));

  // L3b
  result.launch_files = launchFiles;
  const l3bParts = [];
  let l3bStatus = 'NOT_DETECTED';
  if (cmFiles.length) { l3bParts.push(`ciphermld in ${cmFiles.length} files`); l3bStatus = 'CONFIRMED'; }
  if (orFiles.length) l3bParts.push(`or-maintainer.peer[32] in ${orFiles.length} files`);
  if (gwFiles.length) { l3bParts.push(`gateway-o UUID in ${gwFiles.length} files`); l3bStatus = 'CONFIRMED'; }
  if (launchFiles.length) { l3bParts.push(`OSLaunchdJob launch mechanism in ${launchFiles.length} files`); l3bStatus = 'CONFIRMED'; }
  addIndicator('L3b', 'Egress Anchor (ciphermld / networkserviceproxy)',
    l3bStatus, 0, l3bParts.join(' \u00B7 ') || 'ciphermld not detected');

  // L5
  const KNOWN_STATIC_RELAY_UUID = '1001A1D3-C12D-4D86-9475-6803804E56B6';
  let staticRelayUUIDs = [];
  for (const [uuid, fileSet] of Object.entries(kayleesUUIDMap)) {
    if (fileSet.size >= 3) staticRelayUUIDs.push({ uuid, files: fileSet.size });
  }
  result.ohf_nodes_found = Object.keys(c2Hits);
  result.c2_hit_counts = c2Hits;
  result.ohf_files = ohfFiles;
  result.kaylees_files = kayleesF;
  result.kaylees_static_relay_uuids = staticRelayUUIDs;
  const l5parts = [];
  let l5status = 'NOT_DETECTED';
  if (ohfFiles.length) { l5parts.push(`ObliviousHopFallback in ${ohfFiles.length} files`); l5status = 'POSSIBLE'; }
  if (Object.keys(c2Hits).length) { l5parts.push(`${Object.keys(c2Hits).length} operator relay domains`); l5status = 'CONFIRMED'; }
  if (kayleesF.length) {
    l5parts.push(`relay endpoint (kaylees.site) in ${kayleesF.length} files`);
    if (l5status === 'NOT_DETECTED') l5status = 'POSSIBLE';
  }
  if (staticRelayUUIDs.length) {
    for (const sr of staticRelayUUIDs) {
      const isKnown = sr.uuid === KNOWN_STATIC_RELAY_UUID;
      l5parts.push(`CONFIRMED static relay — UUID ${sr.uuid} in ${sr.files} files${isKnown ? ' [known IOC]' : ''}`);
    }
    l5status = 'CONFIRMED';
  }
  addIndicator('L5', 'Active Egress (Relay Mesh / Digital Twin)',
    l5status, 0, l5parts.join(' \u00B7 ') || 'No relay sessions detected');

  // L6
  result.ifsample_files = ifSampleFiles;
  result.seymour_files = seymourFiles;
  let l6status = 'NOT_DETECTED', l6parts = [];
  if (ifSampleFiles.length >= 2 && bearerTotal > 100) {
    l6parts.push(`IfSample rx-bytes 0 falsification in ${ifSampleFiles.length} files`);
    l6status = 'POSSIBLE';
  }
  if (seymourFiles.length >= 2) {
    l6parts.push(`suppression cache (seymour) in ${seymourFiles.length} files`);
    if (l6status === 'NOT_DETECTED') l6status = 'POSSIBLE';
  }
  if (!pmuText) {
    if (!l6parts.length) { l6status = 'ERROR'; l6parts = ['pmudiagnose.txt not found']; }
  } else {
    const thermalZero = IOCS.pmu_thermal_regions.every(r => regionAllZero(pmuText, r) === true);
    const pmuActive = IOCS.pmu_active_regions.some(r => regionAllZero(pmuText, r) === false);
    const spmiZero = regionAllZero(pmuText, '8') === true;
    if (pmuActive && thermalZero) {
      l6parts.unshift(`PMU live — thermal regions ALL ZERO — diagnostic suppression active`);
      l6status = 'CONFIRMED';
      result.simulated_reality = true;
    }
    if (spmiZero && pmuActive) l6parts.push('SPMI counters all zero while PMU active');
    if (!l6parts.length) l6parts = ['PMU thermal registers appear normal'];
  }
  addIndicator('L6', 'Diagnostic Suppression', l6status, 0, l6parts.join(' \u00B7 '));

  // Score
  const confirmed = result.indicators.filter(i => i.status === 'CONFIRMED').length;
  result.confirmed_count = confirmed;
  if (confirmed >= 6) result.verdict = 'SURVEILLANCE FRAMEWORK ACTIVE';
  else if (confirmed >= 3) result.verdict = 'INDICATORS CONFIRMED \u2014 REVIEW REQUIRED';
  else if (confirmed >= 1) result.verdict = 'SUSPICIOUS \u2014 SOME INDICATORS PRESENT';
  else result.verdict = 'NO INDICATORS DETECTED \u2014 DEVICE APPEARS CLEAN';

  return { result, harvestedUUIDs: [...harvestedUUIDs] };
}

// ── Message handler ──
self.onmessage = async function(e) {
  const { type, payload } = e.data;

  if (type === 'decompress_and_parse') {
    try {
      const { tracev3Files, pmuText, dscBlobs } = await decompressAndParse(payload.fileBuffer);
      // Transfer dscBlobs as transferable buffers
      const dscEntries = {};
      const transfers = [];
      for (const [k, v] of Object.entries(dscBlobs)) {
        dscEntries[k] = v.buffer;
        transfers.push(v.buffer);
      }
      self.postMessage({
        type: 'parsed',
        tracev3Files,
        pmuText,
        dscBlobs: dscEntries,
        fileCount: Object.keys(tracev3Files).length
      }, transfers);
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message || String(err) });
    }
  }

  if (type === 'scan') {
    try {
      // Reconstruct dscBlobs as Uint8Arrays from transferred buffers
      const dscBlobs = {};
      for (const [k, buf] of Object.entries(payload.dscBlobs || {})) {
        dscBlobs[k] = new Uint8Array(buf);
      }
      const { result, harvestedUUIDs } = scanTracev3(
        payload.tracev3Files,
        payload.IOCS,
        payload.pmuText
      );
      self.postMessage({
        type: 'scan_done',
        result,
        harvestedUUIDs,
        dscBlobs
      });
    } catch (err) {
      self.postMessage({ type: 'error', message: err.message || String(err) });
    }
  }
};
