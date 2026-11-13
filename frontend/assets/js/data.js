/* SentinelTI — agent descriptions, plus example data shown to visitors who are not signed in. */
window.SentinelData = {
  agents: [
    {
      id: 'triage', n: '01', name: 'Triage Agent',
      aim: 'Identifies the real file type from magic bytes, computes SHA-256 and checks size before anything else runs.',
      tools: ['Magic bytes', 'SHA-256', 'ssdeep', 'Pydantic'],
      out: 'Validated sample handle, file class, fingerprint',
    },
    {
      id: 'evidence', n: '02', name: 'Evidence Agent',
      aim: 'Extracts structured evidence — PE metadata, sections, imports and YARA matches. Structured evidence, not a vague LLM output.',
      tools: ['LIEF', 'yara-python', 'Strings & IOCs', 'Entropy'],
      out: 'Headers, sections, imports, strings, rule hits',
    },
    {
      id: 'behaviour', n: '03', name: 'Behaviour Hypothesis Agent',
      aim: 'Correlates APIs, strings, imports/exports and section anomalies to detect capabilities proven by behaviour.',
      tools: ['API correlation', 'Capability rules', 'Anomaly scoring'],
      out: 'Capabilities with supporting evidence',
    },
    {
      id: 'context', n: '04', name: 'Threat Context Agent',
      aim: 'Maps supported findings to MITRE ATT&CK techniques and retrieves matching internal intelligence notes.',
      tools: ['MITRE ATT&CK', 'Threat intel RAG', 'VirusTotal'],
      out: 'Technique IDs, family, related reports',
    },
    {
      id: 'report', n: '05', name: 'Explainability & PDF Agent',
      aim: 'Verifies every fact once, builds the evidence graph and renders the explainable PDF report.',
      tools: ['Neo4j graph', 'Fact check', 'PDF render'],
      out: 'Attack graph, narrative, PDF report',
    },
  ],

  tools: [
    { name: 'LIEF', use: 'Parses PE, ELF and Mach-O headers, sections, imports and exports.', agent: '02', art: 'entropy' },
    { name: 'YARA', use: 'Matches files against a rule set you can extend with your own rules.', agent: '02', art: 'yara' },
    { name: 'Strings & IOCs', use: 'Pulls ASCII and UTF-16 strings, then URLs, IPs, domains and registry keys.', agent: '02', art: 'strings' },
    { name: 'Fuzzy hashes', use: 'ssdeep and import hashes find samples that share structure.', agent: '01', art: 'hash' },
    { name: 'FLOSS', use: 'Optional add-on that recovers stack and decoded strings from obfuscated code.', agent: '02', art: 'hex' },
    { name: 'Capability rules', use: 'Correlates APIs and strings into capabilities, with the proof attached.', agent: '03', art: 'chain' },
    { name: 'Import inspector', use: 'Lets an agent check the import table when something looks incomplete.', agent: '03', art: 'imports' },
    { name: 'MITRE ATT&CK', use: 'Maps proven capabilities to techniques from a local catalogue.', agent: '04', art: 'attck' },
    { name: 'Threat notes', use: 'Searches your own internal notes and reference documents.', agent: '04', art: 'radar' },
    { name: 'VirusTotal', use: 'Looks up existing detections by hash. The file is never uploaded.', agent: '04', art: 'rep' },
    { name: 'AlienVault OTX', use: 'Checks community threat pulses for the same hash.', agent: '04', art: 'rep' },
    { name: 'Neo4j graph', use: 'Links samples that share indicators, privately for each user.', agent: '05', art: 'graph' },
    { name: 'PDF report', use: 'Publishes the verdict, evidence and defanged indicators as a PDF.', agent: '05', art: 'pdf' },
  ],

  samples: [
    { file: 'invoice_0923.exe', family: 'Emotet.Loader', verdict: 'Critical', tone: 'crit', risk: 94, ago: '4m ago', sig: [.95, .9, .97, .88, .93] },
    { file: 'update_helper.dll', family: 'Cobalt Strike Beacon', verdict: 'Critical', tone: 'crit', risk: 91, ago: '22m ago', sig: [.9, .86, .92, .95, .9] },
    { file: 'setup_x64.msi', family: 'AgentTesla', verdict: 'Malicious', tone: 'crit', risk: 82, ago: '1h ago', sig: [.7, .84, .8, .76, .82] },
    { file: 'report_q3.docm', family: 'Macro Dropper', verdict: 'Suspicious', tone: 'warn', risk: 61, ago: '3h ago', sig: [.5, .66, .58, .62, .6] },
    { file: 'putty.exe', family: 'Signed Utility', verdict: 'Clean', tone: 'ok', risk: 4, ago: '5h ago', sig: [.06, .04, .02, .03, .05] },
    { file: 'svc_patch.bin', family: 'UPX Packed', verdict: 'Suspicious', tone: 'warn', risk: 57, ago: '1d ago', sig: [.42, .7, .5, .46, .55] },
    { file: 'chrome_installer.exe', family: 'Signed Installer', verdict: 'Clean', tone: 'ok', risk: 7, ago: '2d ago', sig: [.1, .06, .04, .05, .08] },
  ],

  // Example evidence graph for invoice_0923.exe
  graph: {
    nodes: [
      { id: 'sample', label: 'invoice_0923.exe', type: 'sample', x: 0, y: 0,
        detail: { title: 'invoice_0923.exe', kind: 'Sample', rows: [['Type', 'PE32 executable (GUI) Intel 80386'], ['SHA-256', 'e3b9…4f1a7c2d9e'], ['Size', '412 KB'], ['Entropy', '7.62 (packed)'], ['Compiled', '2026-10-22 03:14 UTC (forged)']],
          text: 'Triage identified a Windows PE disguised as an invoice. High overall entropy and a forged timestamp were passed to the Evidence Agent.' } },
      { id: 'upx', label: 'UPX0 / UPX1', type: 'evidence', x: -260, y: -150,
        detail: { title: 'Packed sections', kind: 'Evidence · Sections', rows: [['Sections', 'UPX0, UPX1, .rsrc'], ['UPX1 entropy', '7.91'], ['Raw size UPX0', '0 bytes'], ['IAT', 'Minimal (3 imports)']],
          text: 'An empty UPX0 section with a high-entropy UPX1 indicates runtime unpacking. The minimal import table hides the real capabilities until execution.' } },
      { id: 'inject', label: 'Process Injection', type: 'capability', x: 260, y: -170,
        detail: { title: 'Process injection', kind: 'Capability · T1055', rows: [['APIs', 'VirtualAllocEx, WriteProcessMemory, CreateRemoteThread'], ['Confidence', '0.93'], ['ATT&CK', 'T1055.002']],
          text: 'The Behaviour Agent correlated three imported APIs that together form the classic remote-thread injection chain into explorer.exe.' } },
      { id: 'persist', label: 'Run-key Persistence', type: 'capability', x: 300, y: 130,
        detail: { title: 'Registry persistence', kind: 'Capability · T1547.001', rows: [['String', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'], ['API', 'RegSetValueExW'], ['Confidence', '0.88']],
          text: 'A Run-key path recovered by FLOSS, combined with RegSetValueExW, shows the sample re-launches itself on every logon.' } },
      { id: 'c2', label: 'C2 Beacon', type: 'network', x: 40, y: 230,
        detail: { title: 'Command & control', kind: 'Network · T1071.001', rows: [['Endpoints', '185.244.25[.]14:8080, 91.92.109[.]3'], ['Protocol', 'HTTP POST, RC4 body'], ['User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0)']],
          text: 'Decoded stack strings revealed two hard-coded endpoints. The Threat Context Agent matched both to known Emotet epoch-5 infrastructure.' } },
      { id: 'yara', label: 'YARA: Emotet_E5', type: 'intel', x: -300, y: 140,
        detail: { title: 'YARA match', kind: 'Pattern · Rule hit', rows: [['Rule', 'Emotet_Epoch5_Loader'], ['ssdeep', '6144:kD3…  (87% similar)'], ['imphash', 'f34d5f2d4577ed6d9ceec516c1f5a744']],
          text: 'Structural rule and fuzzy-hash similarity both point to the Emotet loader family, independent of the behavioural evidence.' } },
      { id: 'family', label: 'Emotet', type: 'intel', x: -40, y: -280,
        detail: { title: 'Attribution: Emotet', kind: 'Threat context', rows: [['Family', 'Emotet (Mealybug / TA542)'], ['First seen', '2014'], ['Related', '14 internal reports']],
          text: 'All supporting findings were verified once by the Explainability Agent before attribution. The final verdict is Critical with risk score 94.' } },
    ],
    edges: [
      ['sample', 'upx'], ['sample', 'inject'], ['sample', 'persist'], ['sample', 'c2'],
      ['upx', 'yara'], ['yara', 'family'], ['inject', 'family'], ['c2', 'persist'], ['sample', 'family'],
    ],
  },
};
