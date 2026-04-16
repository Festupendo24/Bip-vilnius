'use strict';

/* ═══════════════════════════════════════════════════════════════
   ReconView — app.js  (language + attack surface map + dashboard)
   ═══════════════════════════════════════════════════════════════ */

// ─── State ────────────────────────────────────────────────────────────────────
const D = {
  domain    : '',
  ip        : null,
  ipInfo    : null,
  whois     : null,
  dns       : {},
  certs     : [],
  headers   : {},
  stack     : [],
  htmlSource: '',
  language  : null,   // { primary:{label,code,urls}, all:[…] }
  findings  : [],
  score     : null,
};

// ─── DOM helpers ──────────────────────────────────────────────────────────────
const el   = id  => document.getElementById(id);
const show = id  => { const e=el(id); if(e) e.style.display=''; };
const hide = id  => { const e=el(id); if(e) e.style.display='none'; };
const esc  = str => String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const pill = (t,c) => `<span class="pill ${c}">${esc(t)}</span>`;
const row  = (l,v) => `<tr><td>${esc(l)}</td><td>${v}</td></tr>`;

// ─── Log helpers ──────────────────────────────────────────────────────────────
const logLines = {};
function logAdd(key, text) {
  const d = document.createElement('div');
  d.className = 'log-line'; d.id = 'log-'+key;
  d.innerHTML = `<div class="log-icon"><div class="spin-sm"></div></div><div class="log-text">${esc(text)}</div><div class="log-status"></div>`;
  el('log-lines').appendChild(d); logLines[key] = d;
}
function logDone(key, html='') { const d=logLines[key]; if(!d) return; d.querySelector('.log-icon').innerHTML='<span style="color:var(--accent)">✓</span>'; d.querySelector('.log-status').innerHTML=html; }
function logFail(key, msg='') { const d=logLines[key]; if(!d) return; d.querySelector('.log-icon').innerHTML='<span style="color:var(--danger)">✗</span>'; d.querySelector('.log-text').style.color='var(--danger)'; if(msg) d.querySelector('.log-status').textContent=msg; }

// ─── Network ──────────────────────────────────────────────────────────────────
const fetchJson = async url => { const r=await fetch(url,{signal:AbortSignal.timeout(12000)}); if(!r.ok) throw new Error('HTTP '+r.status); return r.json(); };
const fetchText = async url => { const r=await fetch(url,{signal:AbortSignal.timeout(12000)}); if(!r.ok) throw new Error('HTTP '+r.status); return r.text(); };

// ─── API wrappers ─────────────────────────────────────────────────────────────
const DNS_TYPES = {A:1,AAAA:28,MX:15,NS:2,TXT:16,CNAME:5,CAA:257};
async function fetchAllDNS(domain) {
  const results={};
  await Promise.allSettled(Object.keys(DNS_TYPES).map(async t => {
    try { const d=await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${DNS_TYPES[t]}`); results[t]=d.Answer||[]; } catch { results[t]=[]; }
  }));
  return results;
}
const fetchIPInfo  = ip     => fetchJson(`https://ipinfo.io/${ip}/json`);
const fetchRDAP    = domain => fetchJson(`https://rdap.org/domain/${domain}`);
const fetchCerts   = domain => fetchJson(`https://crt.sh/?q=%25.${domain}&output=json`);
const fetchHeaders = domain => fetchText(`https://api.hackertarget.com/httpheaders/?q=https://${domain}`);
const fetchSource  = domain => fetchText(`https://api.hackertarget.com/pagelinks/?q=https://${domain}`);

// ─── Header parsing ───────────────────────────────────────────────────────────
function parseHeaders(text) {
  const h={};
  for (const line of text.split('\n')) { const i=line.indexOf(':'); if(i>0){const k=line.slice(0,i).trim().toLowerCase(),v=line.slice(i+1).trim(); if(k&&v) h[k]=v;} }
  return h;
}
const SEC_HEADERS = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','x-xss-protection'];
const countSecHeaders = h => SEC_HEADERS.filter(s=>h[s]).length;

// ─── Language detection ───────────────────────────────────────────────────────
const LANG_NAMES = {en:'English',pt:'Portuguese',es:'Spanish',fr:'French',de:'German',it:'Italian',nl:'Dutch',pl:'Polish',ru:'Russian',zh:'Chinese',ja:'Japanese',ko:'Korean',ar:'Arabic',tr:'Turkish',sv:'Swedish',da:'Danish',fi:'Finnish',nb:'Norwegian',cs:'Czech',ro:'Romanian',hu:'Hungarian',el:'Greek',uk:'Ukrainian',he:'Hebrew',id:'Indonesian',ms:'Malay',th:'Thai',vi:'Vietnamese',hi:'Hindi',ca:'Catalan',hr:'Croatian',sk:'Slovak',sl:'Slovenian',bg:'Bulgarian',lt:'Lithuanian',lv:'Latvian',et:'Estonian'};

function detectLanguage(headers, html) {
  const langMap = new Map();
  const add = (code, url='') => {
    if (!code||code==='x-default') return;
    const base=code.toLowerCase().split('-')[0];
    const label=LANG_NAMES[base]||code.toUpperCase();
    if (!langMap.has(base)) langMap.set(base,{label,code:base,urls:[]});
    if (url) langMap.get(base).urls.push(url);
  };
  // 1. Content-Language header
  (headers['content-language']||'').split(',').map(s=>s.trim()).filter(Boolean).forEach(c=>add(c));
  // 2. <html lang="…">
  const htmlLang = html.match(/<html[^>]+lang=["']([^"']+)["']/i);
  if (htmlLang) add(htmlLang[1]);
  // 3. hreflang tags
  const re = /<link[^>]+hreflang=["']([^"']+)["'][^>]*href=["']([^"']+)["'][^>]*>|<link[^>]+href=["']([^"']+)["'][^>]*hreflang=["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m=re.exec(html))!==null) add(m[1]||m[4], m[2]||m[3]);
  // 4. <meta name="language">
  const metaLang = html.match(/<meta[^>]+name=["']language["'][^>]+content=["']([^"']+)["']/i);
  if (metaLang) add(metaLang[1]);
  // 5. URL path patterns /en/ /fr/ etc.
  const urlRe = /href=["'][^"']*\/(en|pt|es|fr|de|it|nl|pl|ru|zh|ja|ko|ar|tr|sv|da|fi|cs|ro|hu|el)\//gi;
  while ((m=urlRe.exec(html))!==null) add(m[1]);
  if (!langMap.size) return null;
  const all = [...langMap.values()];
  const base = htmlLang ? htmlLang[1].toLowerCase().split('-')[0] : null;
  const primary = (base&&langMap.has(base)) ? langMap.get(base) : all[0];
  return { primary, all };
}

// ─── Tech stack detection ─────────────────────────────────────────────────────
const STACK_RULES = [
  {name:'PHP',         cat:'Language',   col:'#7A86B8',fn:(h,s)=>h['x-powered-by']?.match(/php/i)?.[0]||s.match(/\.php["'?]/)?.[0]||(h['set-cookie']?.includes('PHPSESS')?'PHPSESSID cookie':null)},
  {name:'Python',      cat:'Language',   col:'#3572A5',fn:(h,s)=>h['x-powered-by']?.match(/python|django|flask|fastapi/i)?.[0]||h['server']?.match(/gunicorn|uvicorn/i)?.[0]||s.match(/django|flask|fastapi/i)?.[0]},
  {name:'Ruby',        cat:'Language',   col:'#CC342D',fn:(h,s)=>h['x-powered-by']?.match(/phusion passenger|ruby/i)?.[0]||h['server']?.match(/passenger|puma|thin/i)?.[0]},
  {name:'Node.js',     cat:'Language',   col:'#5FA04E',fn:(h,s)=>h['x-powered-by']?.match(/express|node/i)?.[0]||s.match(/express|next\.js|nuxt/i)?.[0]},
  {name:'Java',        cat:'Language',   col:'#B07219',fn:(h,s)=>h['x-powered-by']?.match(/servlet|jsp|java|spring/i)?.[0]||h['server']?.match(/tomcat|jetty|jboss/i)?.[0]||h['set-cookie']?.match(/jsessionid/i)?.[0]},
  {name:'.NET',        cat:'Language',   col:'#512BD4',fn:(h,s)=>h['x-powered-by']?.match(/asp\.net|mono/i)?.[0]||h['x-aspnet-version']||h['set-cookie']?.match(/asp\.net_sessionid/i)?.[0]},
  {name:'Go',          cat:'Language',   col:'#00ADD8',fn:(h,s)=>h['server']?.match(/^go /i)?.[0]||s.match(/gorilla|gin-gonic/i)?.[0]},
  {name:'nginx',       cat:'Web server', col:'#009900',fn:(h)=>h['server']?.match(/nginx/i)?.[0]},
  {name:'Apache',      cat:'Web server', col:'#D22128',fn:(h)=>h['server']?.match(/apache/i)?.[0]},
  {name:'Caddy',       cat:'Web server', col:'#1FBBFF',fn:(h)=>h['server']?.match(/caddy/i)?.[0]},
  {name:'IIS',         cat:'Web server', col:'#0078D4',fn:(h)=>h['server']?.match(/microsoft-iis/i)?.[0]},
  {name:'LiteSpeed',   cat:'Web server', col:'#FF6600',fn:(h)=>h['server']?.match(/litespeed/i)?.[0]||h['x-litespeed-cache']},
  {name:'Cloudflare',  cat:'CDN',        col:'#F48024',fn:(h)=>h['cf-ray']||h['server']?.match(/cloudflare/i)?.[0]||h['cf-cache-status']},
  {name:'Vercel',      cat:'CDN',        col:'#555555',fn:(h)=>h['x-vercel-id']||h['server']?.match(/vercel/i)?.[0]},
  {name:'Netlify',     cat:'CDN',        col:'#00C7B7',fn:(h)=>h['x-nf-request-id']||h['server']?.match(/netlify/i)?.[0]},
  {name:'AWS CloudFront',cat:'CDN',      col:'#FF9900',fn:(h)=>h['x-amz-cf-id']||h['via']?.match(/cloudfront/i)?.[0]},
  {name:'Fastly',      cat:'CDN',        col:'#FF282D',fn:(h)=>h['x-fastly-request-id']},
  {name:'GitHub Pages',cat:'Hosting',    col:'#333333',fn:(h)=>h['x-github-request-id']||h['server']?.match(/github/i)?.[0]},
  {name:'WordPress',   cat:'CMS',        col:'#21759B',fn:(h,s)=>s.match(/wp-content|wp-includes|xmlrpc\.php/i)?.[0]||h['x-powered-by']?.match(/wordpress/i)?.[0]},
  {name:'Drupal',      cat:'CMS',        col:'#0678BE',fn:(h,s)=>h['x-generator']?.match(/drupal/i)?.[0]||s.match(/drupal/i)?.[0]},
  {name:'Joomla',      cat:'CMS',        col:'#F44321',fn:(h,s)=>s.match(/joomla/i)?.[0]||h['set-cookie']?.match(/joomla/i)?.[0]},
  {name:'Ghost',       cat:'CMS',        col:'#738A94',fn:(h,s)=>h['x-ghost-cache-status']||s.match(/ghost\.org|ghost-theme/i)?.[0]},
  {name:'Next.js',     cat:'Framework',  col:'#333333',fn:(h,s)=>h['x-nextjs-cache']||h['x-powered-by']?.match(/next\.js/i)?.[0]||s.match(/_next\/static/)?.[0]},
  {name:'Nuxt',        cat:'Framework',  col:'#00DC82',fn:(h,s)=>h['x-powered-by']?.match(/nuxt/i)?.[0]||s.match(/_nuxt\//)?.[0]},
  {name:'React',       cat:'Framework',  col:'#61DAFB',fn:(h,s)=>s.match(/react\.development|react\.production|react-dom/i)?.[0]},
  {name:'Vue.js',      cat:'Framework',  col:'#4FC08D',fn:(h,s)=>s.match(/vue\.js|vue\.min\.js|\/vue@/i)?.[0]},
  {name:'Angular',     cat:'Framework',  col:'#DD0031',fn:(h,s)=>s.match(/angular\.min\.js|ng-version|@angular/i)?.[0]},
  {name:'Svelte',      cat:'Framework',  col:'#FF3E00',fn:(h,s)=>s.match(/svelte/i)?.[0]},
  {name:'Laravel',     cat:'Framework',  col:'#FF2D20',fn:(h,s)=>h['set-cookie']?.match(/laravel_session/i)?.[0]||s.match(/laravel/i)?.[0]},
  {name:'Django',      cat:'Framework',  col:'#092E20',fn:(h,s)=>h['set-cookie']?.match(/csrftoken/i)?.[0]||s.match(/django/i)?.[0]},
  {name:'Shopify',     cat:'E-commerce', col:'#96BF48',fn:(h,s)=>h['x-shopify-stage']||s.match(/cdn\.shopify\.com|Shopify\.theme/i)?.[0]},
  {name:'WooCommerce', cat:'E-commerce', col:'#96588A',fn:(h,s)=>s.match(/woocommerce|wc-ajax/i)?.[0]},
  {name:'Magento',     cat:'E-commerce', col:'#EE672F',fn:(h,s)=>s.match(/mage\/|Magento/i)?.[0]||h['set-cookie']?.match(/mage-/i)?.[0]},
  {name:'Google Analytics',cat:'Analytics',col:'#E37400',fn:(h,s)=>s.match(/google-analytics\.com\/analytics\.js|gtag\/js|UA-\d|G-[A-Z0-9]/i)?.[0]},
  {name:'Google Tag Manager',cat:'Analytics',col:'#4285F4',fn:(h,s)=>s.match(/googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]/i)?.[0]},
  {name:'HubSpot',     cat:'Marketing',  col:'#FF7A59',fn:(h,s)=>s.match(/js\.hs-scripts\.com|hubspot/i)?.[0]},
  {name:'Intercom',    cat:'Marketing',  col:'#1F8DED',fn:(h,s)=>s.match(/widget\.intercom\.io|intercomSettings/i)?.[0]},
  {name:'Hotjar',      cat:'Analytics',  col:'#FD3A5C',fn:(h,s)=>s.match(/hotjar\.com|hjid/i)?.[0]},
  {name:'Segment',     cat:'Analytics',  col:'#52BD94',fn:(h,s)=>s.match(/cdn\.segment\.com/i)?.[0]},
  {name:'Varnish',     cat:'Cache',      col:'#4591D3',fn:(h)=>h['x-varnish']||h['via']?.match(/varnish/i)?.[0]},
];

function detectStack(headers, html) {
  const s = html.slice(0, 60000), hits = [];
  for (const rule of STACK_RULES) { try { const ev=rule.fn(headers,s); if(ev) hits.push({name:rule.name,category:rule.cat,color:rule.col,evidence:String(ev).slice(0,80)}); } catch {} }
  const ord=['Language','Web server','CDN','Hosting','CMS','Framework','E-commerce','Analytics','Marketing','Cache'];
  return hits.sort((a,b)=>(ord.indexOf(a.category)-ord.indexOf(b.category))||a.name.localeCompare(b.name));
}

// ─── Score ────────────────────────────────────────────────────────────────────
function computeScore() {
  let s=100;
  for (const f of D.findings) { if(f.sev==='HIGH') s-=15; else if(f.sev==='MEDIUM') s-=7; else s-=3; }
  return Math.max(0, Math.min(100, s));
}
function scoreGrade(s) {
  if(s>=90) return {grade:'A',cls:'risk-lo'};
  if(s>=75) return {grade:'B',cls:'risk-lo'};
  if(s>=55) return {grade:'C',cls:'risk-med'};
  if(s>=35) return {grade:'D',cls:'risk-med'};
  return {grade:'F',cls:'risk-hi'};
}

// ─── Findings engine ──────────────────────────────────────────────────────────
function generateFindings() {
  D.findings=[];
  const add=(sev,title,detail)=>D.findings.push({sev,title,detail});
  const txt=(D.dns.TXT||[]).map(r=>r.data||'');
  const dmarc=txt.find(t=>t.includes('v=DMARC1'));
  if(!dmarc) add('HIGH','No DMARC record found','Without DMARC, attackers can spoof emails from this domain. Add a TXT record at _dmarc with at minimum p=none.');
  else if(dmarc.includes('p=none')) add('MEDIUM','DMARC policy is p=none (not enforced)','DMARC exists but does not block spoofed email. Upgrade to p=quarantine or p=reject.');
  const spf=txt.find(t=>t.startsWith('v=spf1'));
  if(!spf) add('HIGH','No SPF record found','Without SPF, any server can send email as this domain.');
  else if(spf.includes('+all')) add('HIGH','SPF uses +all (permits all senders)','Change to ~all (softfail) or -all (fail).');
  if(D.dns.A?.length&&!D.dns.AAAA?.length) add('LOW','No IPv6 (AAAA) record','No IPv6 address. IPv6 adoption improves resilience.');
  if(!D.dns.CAA?.length) add('MEDIUM','No CAA record','Without CAA, any CA can issue certificates for this domain.');
  if(Object.keys(D.headers).length) {
    if(!D.headers['strict-transport-security']) add('HIGH','Missing HSTS header','Without HSTS, browsers may connect over HTTP initially, enabling downgrade attacks.');
    if(!D.headers['content-security-policy'])   add('MEDIUM','Missing Content-Security-Policy','CSP mitigates XSS attacks by restricting which resources a page may load.');
    if(!D.headers['x-frame-options']&&!D.headers['content-security-policy']?.includes('frame-ancestors')) add('MEDIUM','Missing clickjacking protection','No X-Frame-Options or frame-ancestors CSP directive found.');
    if(!D.headers['x-content-type-options'])    add('LOW','Missing X-Content-Type-Options','Without nosniff, MIME-type sniffing is possible.');
    if(!D.headers['referrer-policy'])            add('LOW','Missing Referrer-Policy','Browsers may leak full URLs to third parties.');
    if(D.headers['server']?.length>4)           add('LOW',`Server header discloses: "${D.headers['server']}"`, 'Server software version aids attacker fingerprinting.');
    if(D.headers['x-powered-by'])               add('LOW',`X-Powered-By leaks: "${D.headers['x-powered-by']}"`, 'Remove X-Powered-By to reduce information leakage.');
  }
  D.findings.sort((a,b)=>({HIGH:0,MEDIUM:1,LOW:2}[a.sev]-{HIGH:0,MEDIUM:1,LOW:2}[b.sev]));
}

// ─── Badge helper ─────────────────────────────────────────────────────────────
function setBadge(mod,cls,val) { const b=el('badge-'+mod); if(!b) return; b.className='module-status '+cls; b.textContent=val; }

// ─── Main scan ────────────────────────────────────────────────────────────────
async function startScan() {
  const raw=el('domainInput').value.trim(); if(!raw){el('domainInput').focus();return;}
  const domain=raw.replace(/^https?:\/\//,'').replace(/\/.*$/,'').replace(/^www\./,'').trim().toLowerCase();
  if(!domain) return;
  el('domainInput').value=domain;
  Object.assign(D,{domain,ip:null,ipInfo:null,whois:null,dns:{},certs:[],headers:{},stack:[],htmlSource:'',language:null,findings:[],score:null});
  el('log-lines').innerHTML=''; Object.keys(logLines).forEach(k=>delete logLines[k]);
  hide('state-empty'); hide('state-results'); show('state-scanning');
  el('log-domain').textContent=domain; el('scanBtn').disabled=true; el('scanBtn').textContent='SCANNING…';
  ['overview','dns','ssl','web','lang','headers','findings','dashboard','attack'].forEach(m=>setBadge(m,'s-loading','…'));

  // DNS
  logAdd('dns','Querying DNS records (dns.google)…');
  try { D.dns=await fetchAllDNS(domain); const c=Object.values(D.dns).flat().length; logDone('dns',pill(c+' records','pill-ok')); setBadge('dns',c>0?'s-ok':'s-warn',c); }
  catch { logFail('dns','failed'); D.dns={}; setBadge('dns','s-idle','err'); }

  // IP
  logAdd('ip','Resolving IP & geolocation…');
  try {
    D.ip=(D.dns.A||[])[0]?.data||null;
    if(D.ip) {
      logDone('ip',`<span style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">${D.ip}</span>`);
      logAdd('ipinfo','Fetching geolocation (ipinfo.io)…');
      try { D.ipInfo=await fetchIPInfo(D.ip); logDone('ipinfo',pill(`${D.ipInfo.country||'?'} · ${D.ipInfo.org||'?'}`,'pill-info')); }
      catch { logFail('ipinfo','unavailable'); }
    } else logFail('ip','no A record');
  } catch { logFail('ip','failed'); }

  // RDAP
  logAdd('rdap','Fetching WHOIS/RDAP…');
  try { D.whois=await fetchRDAP(domain); logDone('rdap',pill('ok','pill-ok')); setBadge('overview','s-ok','ok'); }
  catch { logFail('rdap','ccTLD or restricted'); D.whois=null; setBadge('overview','s-warn','ok'); }

  // Certs
  logAdd('crt','Querying certificate transparency (crt.sh)…');
  try {
    const raw=await fetchCerts(domain); const seen=new Set();
    D.certs=raw.filter(c=>{const k=c.name_value;if(seen.has(k))return false;seen.add(k);return true;}).sort((a,b)=>new Date(b.not_before)-new Date(a.not_before));
    logDone('crt',pill(D.certs.length+' certs','pill-ok')); setBadge('ssl','s-ok',D.certs.length);
  } catch { logFail('crt','unavailable'); D.certs=[]; setBadge('ssl','s-warn','?'); }

  // Headers
  logAdd('headers','Fetching HTTP headers (hackertarget)…');
  try {
    D.headers=parseHeaders(await fetchHeaders(domain));
    const sc=countSecHeaders(D.headers);
    logDone('headers',pill(Object.keys(D.headers).length+' headers','pill-info'));
    setBadge('headers',sc>=4?'s-ok':sc>=2?'s-warn':'s-err',Object.keys(D.headers).length);
  } catch { logFail('headers','blocked/rate-limited'); D.headers={}; setBadge('headers','s-idle','?'); }

  // Source → stack + language
  logAdd('source','Fetching page source…');
  try { D.htmlSource=await fetchSource(domain); logDone('source',pill('ok','pill-ok')); }
  catch { logFail('source','blocked'); D.htmlSource=''; }

  logAdd('stack','Detecting technology stack…');
  try {
    D.stack=detectStack(D.headers,D.htmlSource);
    logDone('stack',pill(D.stack.length+' technologies',D.stack.length>0?'pill-ok':'pill-info'));
    setBadge('web',D.stack.length>0?'s-ok':'s-idle',D.stack.length);
  } catch { logFail('stack','failed'); D.stack=[]; setBadge('web','s-idle','?'); }

  logAdd('lang','Detecting site language & translations…');
  try {
    D.language=detectLanguage(D.headers,D.htmlSource);
    if(D.language) { const c=D.language.all.length; logDone('lang',pill(c+(c>1?' languages':' language'),'pill-ok')); setBadge('lang','s-ok',c); }
    else { logFail('lang','not detected'); setBadge('lang','s-idle','—'); }
  } catch { logFail('lang','failed'); D.language=null; setBadge('lang','s-idle','—'); }

  // Findings + score
  logAdd('findings','Analysing security posture…');
  generateFindings(); D.score=computeScore();
  const fc=D.findings.length;
  logDone('findings',pill(fc+' issues',fc>0?'pill-err':'pill-ok'));
  setBadge('findings',fc>2?'s-err':fc>0?'s-warn':'s-ok',fc);
  setBadge('dashboard','s-ok','→'); setBadge('attack','s-ok','→');

  renderResults();
  hide('state-scanning'); show('state-results');
  el('scanBtn').disabled=false; el('scanBtn').textContent='RESCAN';
  switchTab('dashboard', document.querySelectorAll('.tab')[0]);
}
function quickScan(d){el('domainInput').value=d;startScan();}

// ═══════════════════════════════════════════════════════════════
// RENDERERS
// ═══════════════════════════════════════════════════════════════
function renderResults() {
  el('r-domain').textContent=D.domain;
  el('r-meta').textContent=[D.ip,D.ipInfo?.org,D.ipInfo?.city,D.ipInfo?.country].filter(Boolean).join(' · ');
  const {grade,cls}=scoreGrade(D.score??100);
  const b=el('r-risk-badge'); b.className='risk-badge '+cls; b.textContent=`Grade ${grade} · ${D.score}/100`;
  el('m-dns').textContent=Object.values(D.dns).flat().length;
  el('m-subs').textContent=new Set((D.certs||[]).flatMap(c=>(c.name_value||'').split('\n').map(s=>s.trim()))).size;
  el('m-stack').textContent=D.stack.length;
  const ms=el('m-stack-sub'); if(ms) ms.textContent=[...new Set(D.stack.map(t=>t.category))].slice(0,2).join(' · ');
  el('m-headers').textContent=Object.keys(D.headers).length?`${countSecHeaders(D.headers)}/7`:'?';
  el('m-lang').textContent=D.language?.all?.length||'?';
  const mls=el('m-lang-sub'); if(mls) mls.textContent=D.language?.primary?.label||'not detected';
  el('m-findings').textContent=D.findings.length;
  const hl=D.findings.filter(f=>f.sev==='HIGH').length, ml=D.findings.filter(f=>f.sev==='MEDIUM').length;
  const mfs=el('m-findings-sub'); if(mfs) mfs.textContent=`${hl} high · ${ml} medium`;
  el('m-findings').style.color=D.findings.length===0?'var(--accent)':hl>0?'var(--danger)':'var(--warn)';
  renderDashboard(); renderAttackMap();
  renderIPTable(); renderWHOIS(); renderDNS(); renderEmailSec();
  renderCerts(); renderStack(); renderLanguage(); renderHeaders(); renderFindings();
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function renderDashboard() {
  const wrap=el('dashboard-wrap'); if(!wrap) return;
  const score=D.score??100;
  const {grade}=scoreGrade(score);
  const hl=D.findings.filter(f=>f.sev==='HIGH').length;
  const ml=D.findings.filter(f=>f.sev==='MEDIUM').length;
  const ll=D.findings.filter(f=>f.sev==='LOW').length;
  const flag=D.ipInfo?.country?String.fromCodePoint(...[...D.ipInfo.country.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)):'';
  const langStr=D.language?D.language.all.map(l=>l.label).join(', '):'—';
  const stackStr=D.stack.slice(0,5).map(t=>t.name).join(', ')+(D.stack.length>5?' …':'');
  const ringColor=score>=75?'var(--accent)':score>=45?'var(--warn)':'var(--danger)';
  const C=2*Math.PI*44;
  const txt=(D.dns.TXT||[]).map(r=>r.data||'');
  const spf=txt.find(t=>t.startsWith('v=spf1')), dmarc=txt.find(t=>t.includes('v=DMARC1'));
  wrap.innerHTML=`
<div class="dashboard-grid">
  <div class="db-card db-score-card">
    <svg width="110" height="110" viewBox="0 0 110 110">
      <circle cx="55" cy="55" r="44" fill="none" stroke="var(--c-border)" stroke-width="8"/>
      <circle cx="55" cy="55" r="44" fill="none" stroke="${ringColor}" stroke-width="8"
        stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${(C*(1-score/100)).toFixed(1)}"
        stroke-linecap="round" transform="rotate(-90 55 55)" style="transition:stroke-dashoffset 0.8s ease"/>
      <text x="55" y="50" text-anchor="middle" fill="var(--c-text)" font-size="28" font-weight="700" font-family="var(--font-mono)">${grade}</text>
      <text x="55" y="68" text-anchor="middle" fill="var(--c-muted)" font-size="12" font-family="var(--font-mono)">${score}/100</text>
    </svg>
    <div class="db-score-label">Security score</div>
    <div class="db-score-sub">${esc(D.domain)}</div>
  </div>
  <div class="db-card">
    <div class="db-card-title">Identity</div>
    <table class="meta-table">
      ${row('Domain',`<span style="font-family:var(--font-mono);font-size:12px">${esc(D.domain)}</span>`)}
      ${row('IP',`<span style="font-family:var(--font-mono);font-size:12px">${esc(D.ip||'—')}</span>`)}
      ${row('Organisation',esc(D.ipInfo?.org||'—'))}
      ${row('Location',`${flag} ${esc([D.ipInfo?.city,D.ipInfo?.country].filter(Boolean).join(', ')||'—')}`)}
      ${row('Language(s)',esc(langStr))}
      ${row('Tech stack',`<span style="font-size:12px">${esc(stackStr||'—')}</span>`)}
    </table>
  </div>
  <div class="db-card">
    <div class="db-card-title">Findings breakdown</div>
    <div class="db-finding-bars">
      <div class="db-bar-row"><span class="db-bar-label">HIGH</span><div class="db-bar-track"><div class="db-bar-fill" style="width:${Math.min(100,hl*15)}%;background:var(--danger)"></div></div><span class="db-bar-count" style="color:var(--danger)">${hl}</span></div>
      <div class="db-bar-row"><span class="db-bar-label">MEDIUM</span><div class="db-bar-track"><div class="db-bar-fill" style="width:${Math.min(100,ml*10)}%;background:var(--warn)"></div></div><span class="db-bar-count" style="color:var(--warn)">${ml}</span></div>
      <div class="db-bar-row"><span class="db-bar-label">LOW</span><div class="db-bar-track"><div class="db-bar-fill" style="width:${Math.min(100,ll*8)}%;background:var(--info)"></div></div><span class="db-bar-count" style="color:var(--info)">${ll}</span></div>
    </div>
    <div style="margin-top:12px"><div class="db-card-title" style="margin-bottom:7px">Top priority</div>
    ${D.findings.slice(0,2).map(f=>`<div class="db-top-finding"><span class="finding-sev ${f.sev==='HIGH'?'sev-high':f.sev==='MEDIUM'?'sev-med':'sev-low'}">${esc(f.sev)}</span><span style="font-size:12px">${esc(f.title)}</span></div>`).join('')||'<div class="no-data">No issues found</div>'}</div>
  </div>
  <div class="db-card">
    <div class="db-card-title">Email &amp; DNS security</div>
    <table class="meta-table">
      ${row('SPF',  spf?pill('present','pill-ok'):pill('missing','pill-err'))}
      ${row('DMARC',!dmarc?pill('missing','pill-err'):dmarc.includes('p=none')?pill('p=none','pill-warn'):pill('enforced','pill-ok'))}
      ${row('CAA',  D.dns.CAA?.length?pill('present','pill-ok'):pill('missing','pill-warn'))}
      ${row('HSTS', D.headers['strict-transport-security']?pill('present','pill-ok'):pill('missing','pill-err'))}
      ${row('Sec headers',pill(`${countSecHeaders(D.headers)}/7`,countSecHeaders(D.headers)>=4?'pill-ok':countSecHeaders(D.headers)>=2?'pill-warn':'pill-err'))}
    </table>
  </div>
  <div class="db-card db-full-width">
    <div class="db-card-title">Recommended actions</div>
    <div class="db-recs">
      ${D.findings.slice(0,6).map((f,i)=>`
        <div class="db-rec-item">
          <div class="db-rec-num">${i+1}</div>
          <div><div class="db-rec-title">${esc(f.title)}</div><div class="db-rec-detail">${esc(f.detail)}</div></div>
        </div>`).join('')||'<div class="no-data" style="padding:8px 0">No issues — security posture looks good.</div>'}
    </div>
  </div>
</div>`;
}

// ─── Attack Surface Map ───────────────────────────────────────────────────────
function renderAttackMap() {
  const wrap=el('attack-wrap'); if(!wrap) return;
  const allSubs=[...new Set((D.certs||[]).flatMap(c=>(c.name_value||'').split('\n').map(s=>s.trim()).filter(Boolean)))];
  const riskySubs=allSubs.filter(s=>/admin|dev|staging|test|vpn|jenkins|gitlab|api|login|auth|ftp|intranet|panel|mail|smtp|webmail/i.test(s));
  const mxRecs=(D.dns.MX||[]).map(r=>r.data||'').filter(Boolean);
  const nsRecs=(D.dns.NS||[]).map(r=>r.data||'').filter(Boolean);
  const cnames=(D.dns.CNAME||[]).map(r=>r.data||'').filter(Boolean);
  const riskChip=(label,r='ok')=>{
    const bg=r==='danger'?'var(--danger-bg)':r==='warn'?'var(--warn-bg)':'var(--accent-bg)';
    const bdr=r==='danger'?'var(--danger)':r==='warn'?'var(--warn)':'var(--accent)';
    const col=r==='danger'?'var(--danger)':r==='warn'?'var(--warn)':'var(--accent-dim)';
    return `<span style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-family:var(--font-mono);font-size:11px;background:${bg};border:0.5px solid ${bdr};color:${col};margin:3px">${esc(label)}</span>`;
  };
  const nodeRisk=l=>/admin|panel|jenkins|gitlab|vpn|intranet/i.test(l)?'danger':/dev|staging|test|api|login|auth|mail|smtp|webmail/i.test(l)?'warn':'ok';
  const section=(title,badge,items,fn)=>items.length===0?'':`
    <div class="atk-section">
      <div class="atk-section-head"><span class="atk-section-title">${esc(title)}</span><span class="pill pill-info">${esc(badge)}</span></div>
      <div class="atk-items">${items.map(fn).join('')}</div>
    </div>`;
  wrap.innerHTML=`
<div class="atk-map">
  <div class="atk-root">
    <div class="atk-root-inner">
      <div style="font-family:var(--font-mono);font-size:15px;font-weight:700;color:var(--c-text)">${esc(D.domain)}</div>
      <div style="font-size:11px;color:var(--c-muted);margin-top:3px">${esc(D.ip||'')}${D.ipInfo?.org?' · '+D.ipInfo.org:''}</div>
      ${D.language?.primary?`<div style="margin-top:6px">${pill('🌐 '+D.language.primary.label,'pill-info')}${D.language.all.length>1?` <span style="font-size:11px;color:var(--c-hint)">+${D.language.all.length-1} more</span>`:''}</div>`:''}
    </div>
  </div>
  <div class="atk-sections">
    ${section('Email infrastructure',mxRecs.length+' MX records',mxRecs,mx=>riskChip(mx,'ok'))}
    ${section('DNS infrastructure',nsRecs.length+' nameservers',nsRecs,ns=>riskChip(ns,'ok'))}
    ${section('CNAME aliases',cnames.length+' targets',cnames,cn=>riskChip(cn,'warn'))}
    ${section('High-risk subdomains',riskySubs.length+' found',riskySubs,s=>riskChip(s,nodeRisk(s)))}
    ${section('Technology surface',D.stack.length+' detected',D.stack,t=>`
      <span style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:11px;background:var(--c-surface);border:0.5px solid var(--c-border);color:var(--c-text);margin:3px">
        <span style="width:7px;height:7px;border-radius:50%;background:${esc(t.color)};flex-shrink:0"></span>${esc(t.name)}<span style="color:var(--c-hint);font-size:10px">${esc(t.category)}</span>
      </span>`)}
    ${D.language?.all?.length>1?`
    <div class="atk-section">
      <div class="atk-section-head"><span class="atk-section-title">Language / localisation surface</span><span class="pill pill-info">${D.language.all.length} languages</span></div>
      <div class="atk-items">${D.language.all.map(l=>riskChip(`${l.label}${l.urls.length?' ('+l.urls.length+' URLs)':''}`, 'ok')).join('')}</div>
      <div class="source-note" style="margin-top:8px">Each language version is a separate URL structure — a wider attack surface with its own potential misconfigurations.</div>
    </div>`:''}
    ${section('Security gaps',D.findings.length+' issues',D.findings,f=>`
      <span style="display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:6px;font-size:12px;background:var(--c-surface);border:0.5px solid var(--c-border);color:var(--c-text);margin:3px;width:100%">
        <span class="finding-sev ${f.sev==='HIGH'?'sev-high':f.sev==='MEDIUM'?'sev-med':'sev-low'}">${esc(f.sev)}</span>${esc(f.title)}
      </span>`)}
  </div>
</div>`;
}

// ─── Individual renderers ─────────────────────────────────────────────────────
function renderIPTable() {
  const t=el('tbl-ip'); if(!t) return;
  if(!D.ip&&!D.ipInfo){t.innerHTML=row('','<div class="no-data">IP info unavailable</div>');return;}
  const i=D.ipInfo||{}, flag=i.country?String.fromCodePoint(...[...i.country.toUpperCase()].map(c=>0x1F1E6+c.charCodeAt(0)-65)):'';
  t.innerHTML=[D.ip?row('IP address',`<span style="font-family:var(--font-mono)">${esc(D.ip)}</span>`):'',i.hostname?row('Hostname',`<span style="font-family:var(--font-mono);font-size:12px">${esc(i.hostname)}</span>`):'',i.org?row('ASN / Org',esc(i.org)):'',i.country?row('Location',`${flag} ${esc([i.city,i.region,i.country].filter(Boolean).join(', '))}`):'',i.timezone?row('Timezone',esc(i.timezone)):''].filter(Boolean).join('');
}

function renderWHOIS() {
  const t=el('tbl-whois'); if(!t) return;
  if(!D.whois){t.innerHTML=row('','<div class="no-data">RDAP data unavailable (ccTLD or restricted registrar)</div>');return;}
  const ev=(D.whois.events||[]).reduce((a,e)=>{a[e.eventAction]=e.eventDate;return a;},{});
  const reg=(D.whois.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
  const name=reg?.vcardArray?.[1]?.find(v=>v[0]==='fn')?.[3]||reg?.handle||'—';
  const fmt=d=>{try{return new Date(d).toISOString().slice(0,10);}catch{return d||'—';}};
  const exp=ev.expiration||ev['domain expiration'];
  const expiring=exp&&new Date(exp)<new Date(Date.now()+60*864e5);
  const expiresVal = exp ? (esc(fmt(exp)) + (expiring ? ' ' + pill('expiring soon','pill-warn') : '')) : '—';
  t.innerHTML=[row('Registrar',esc(name)),row('Registered',esc(fmt(ev.registration||ev['last changed']||''))),row('Expires',expiresVal),row('Status',`<span style="font-family:var(--font-mono);font-size:11px">${esc((D.whois.status||[]).join(', ')||'—')}</span>`),D.whois.handle?row('Handle',`<span style="font-family:var(--font-mono);font-size:11px">${esc(D.whois.handle)}</span>`):'',row('Source',pill('rdap.org','pill-info'))].filter(Boolean).join('');
}

const DNS_INFO={A:{title:'A Record — IPv4 Address',desc:'Maps the domain to a version 4 IP address.',osint:'Allows reverse IP lookups, ASN identification, and geolocation of hosting.'},AAAA:{title:'AAAA Record — IPv6',desc:'IPv6 address for the domain.',osint:'Absence may indicate older infrastructure.'},MX:{title:'MX Record — Mail Exchanger',desc:'Defines which server handles email for this domain.',osint:'Reveals email provider and potential phishing vectors.'},NS:{title:'NS Record — Nameserver',desc:'Authoritative DNS servers for this domain.',osint:'Compromised NS record can lead to complete domain hijacking.'},TXT:{title:'TXT Record — Free Text',desc:'Used for SPF, DMARC, DKIM and ownership verification.',osint:'Exposes services in use. Misconfiguration enables email spoofing.'},CNAME:{title:'CNAME Record — Alias',desc:'Points a subdomain to another domain.',osint:'CNAMEs to deleted services may be vulnerable to subdomain takeover.'},CAA:{title:'CAA — CA Authorization',desc:'Restricts which CAs can issue SSL certs for this domain.',osint:'Absence means any CA can issue — increasing risk of fraudulent certs.'}};

function renderDNS() {
  const g=el('dns-grid'); if(!g) return;
  const allRecs=[], cols={A:'#185FA5',AAAA:'#533AB7',MX:'#0F6E56',NS:'#BA7517',TXT:'#A32D2D',CNAME:'#3B6D11',CAA:'#5DCAA5'};
  for(const[type,recs]of Object.entries(D.dns)) for(const r of(recs||[])) allRecs.push({type,data:r.data,ttl:r.TTL});
  if(!allRecs.length){g.innerHTML='<div class="no-data">No DNS records returned</div>';return;}
  g.innerHTML=allRecs.map(r=>{
    const col=cols[r.type]||'#888', info=DNS_INFO[r.type];
    const tip=info?`<div class="tip"><div class="tip-title">${esc(info.title)}</div>${esc(info.desc)}<div class="tip-osint">🔍 ${esc(info.osint)}</div><div class="tip-source">source: dns.google · TTL ${r.ttl||'?'}s</div></div>`:'';
    return `<div class="dns-row has-tooltip"><span class="dns-type" style="background:${col}22;color:${col}">${esc(r.type)}</span><span class="dns-val">${esc(r.data)}</span><span class="dns-ttl">TTL ${r.ttl||'?'}</span>${tip}</div>`;
  }).join('');
}

function renderEmailSec() {
  const t=el('tbl-email-sec'); if(!t) return;
  const txt=(D.dns.TXT||[]).map(r=>r.data||''), mx=(D.dns.MX||[]).map(r=>r.data||'');
  const spf=txt.find(t=>t.startsWith('v=spf1'))||null, dmarc=txt.find(t=>t.includes('v=DMARC1'))||null, dkim=txt.find(t=>t.includes('DKIM')||t.includes('v=DKIM1'))||null;
  const dmP=!dmarc?pill('missing','pill-err'):dmarc.includes('p=none')?pill('p=none','pill-warn'):dmarc.includes('p=quarantine')?pill('p=quarantine','pill-ok'):pill('p=reject','pill-ok');
  t.innerHTML=[row('MX records',mx.length?`<span style="font-family:var(--font-mono);font-size:11px">${mx.map(esc).join('<br>')}</span>`:pill('none','pill-warn')),row('SPF',spf?`${pill('present','pill-ok')} <span style="font-family:var(--font-mono);font-size:10px;color:var(--c-muted)">${esc(spf.slice(0,70))}</span>`:pill('missing','pill-err')),row('DMARC',dmP),row('DKIM',dkim?pill('found in TXT','pill-ok'):`${pill('not found in TXT','pill-warn')} <span style="font-size:11px;color:var(--c-hint)">(selector-specific)</span>`)].join('');
}

function renderLanguage() {
  const wrap=el('lang-wrap'); if(!wrap) return;
  if(!D.language){wrap.innerHTML='<div class="no-data">No language information detected — Content-Language header absent and no hreflang tags found in page source.</div>';return;}
  const{primary,all}=D.language;
  wrap.innerHTML=`
  <div style="margin-bottom:14px">
    <div style="font-size:10px;font-family:var(--font-mono);letter-spacing:0.12em;text-transform:uppercase;color:var(--c-hint);margin-bottom:8px">Primary language</div>
    <div style="display:inline-flex;align-items:center;gap:8px;padding:8px 14px;background:var(--accent-bg);border-radius:8px;border:0.5px solid var(--accent)">
      <span style="font-size:14px;font-weight:600;color:var(--accent-dim)">${esc(primary.label)}</span>
      <span style="font-family:var(--font-mono);font-size:11px;color:var(--c-hint)">${esc(primary.code)}</span>
    </div>
  </div>
  ${all.length>1?`
  <div>
    <div style="font-size:10px;font-family:var(--font-mono);letter-spacing:0.12em;text-transform:uppercase;color:var(--c-hint);margin-bottom:8px">All detected languages (hreflang)</div>
    <div style="display:flex;flex-direction:column;gap:5px">
      ${all.map(l=>`
        <div style="display:flex;align-items:center;gap:10px;padding:8px 11px;background:var(--c-surface);border-radius:8px;border:0.5px solid var(--c-border)">
          <span style="font-size:13px;font-weight:500;color:var(--c-text);min-width:100px">${esc(l.label)}</span>
          <span style="font-family:var(--font-mono);font-size:11px;color:var(--c-hint);min-width:32px">${esc(l.code)}</span>
          ${l.urls.length?`<span style="font-size:11px;color:var(--info)">${l.urls.length} URL${l.urls.length>1?'s':''}</span>`:''}
          ${l.urls[0]?`<a href="${esc(l.urls[0])}" style="font-size:10px;color:var(--c-hint);margin-left:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px" target="_blank" rel="noopener">${esc(l.urls[0])}</a>`:''}
        </div>`).join('')}
    </div>
    <p class="source-note">Source: hreflang &lt;link&gt; tags in page source. Each language version is a separate URL structure with its own potential misconfigurations.</p>
  </div>`:''}`;
}

const SUB_KEYWORDS={mail:{risk:false,explain:'Mail server.'},webmail:{risk:true,explain:'Webmail — target for credential stuffing.'},vpn:{risk:true,explain:'VPN concentrator — remote internal entry point.'},admin:{risk:true,explain:'Admin panel — high-value target.'},panel:{risk:true,explain:'Control panel — potentially sensitive.'},api:{risk:false,explain:'API endpoint — verify authentication.'},dev:{risk:true,explain:'Dev environment — weaker protections than production.'},staging:{risk:true,explain:'Staging — may hold real data.'},test:{risk:true,explain:'Test environment — often forgotten.'},git:{risk:true,explain:'Git server — source code exposure.'},jenkins:{risk:true,explain:'CI/CD — compromise means pipeline takeover.'},gitlab:{risk:true,explain:'GitLab — code and pipeline exposure.'},jira:{risk:false,explain:'Project management.'},confluence:{risk:false,explain:'Internal wiki.'},ftp:{risk:true,explain:'FTP — insecure plaintext protocol.'},intranet:{risk:true,explain:'Intranet exposed externally — network segmentation failure.'},internal:{risk:true,explain:'Internal resource — verify if public.'},login:{risk:true,explain:'Login page — brute force target.'},auth:{risk:true,explain:'Auth server — critical control point.'},sso:{risk:true,explain:'SSO — compromise affects all services.'}};

function classifySub(name,root){
  if(name.startsWith('*.')) return{label:'wildcard',cls:'pill-warn',explain:'Wildcard certificate — covers all possible subdomains.'};
  const sub=name.replace('*.','').replace('.'+root,'').replace(root,'');
  if(!sub||sub===name) return{label:'apex',cls:'pill-info',explain:'Apex (root) domain without subdomain prefix.'};
  for(const[kw,info]of Object.entries(SUB_KEYWORDS)) if(sub.toLowerCase().includes(kw)) return{label:info.risk?'attention':'info',cls:info.risk?'pill-warn':'pill-info',explain:info.explain};
  return{label:'subdomain',cls:'pill-ok',explain:'Subdomain found in SSL certificate transparency logs.'};
}

function renderCerts(){
  const wrap=el('cert-list-wrap'); if(!wrap) return;
  if(!D.certs.length){wrap.innerHTML='<div class="no-data">No certificate transparency data found</div>';return;}
  const subMap=new Map();
  for(const c of D.certs){const names=(c.name_value||'').split('\n').map(s=>s.trim()).filter(Boolean),issuer=(c.issuer_name||'').match(/O=([^,]+)/)?.[1]||c.issuer_name||'?',date=c.not_before?c.not_before.slice(0,10):'—';for(const n of names){if(!subMap.has(n))subMap.set(n,{issuer,date,count:1});else subMap.get(n).count++;}}
  const sorted=[...subMap.entries()].sort((a,b)=>a[0].localeCompare(b[0]));
  wrap.innerHTML=`<div class="cert-list">${sorted.slice(0,100).map(([name,meta])=>{const cls=classifySub(name,D.domain);return`<div class="cert-item has-tooltip"><span class="cert-domain" style="${name.startsWith('*.')?'color:var(--warn)':''}">${esc(name)}</span><span class="pill ${cls.cls}" style="font-size:10px;flex-shrink:0">${esc(cls.label)}</span><span class="cert-issuer" title="${esc(meta.issuer)}">${esc(meta.issuer.slice(0,22))}</span><span class="cert-date">${esc(meta.date)}</span><div class="tip tip-right"><div class="tip-title">Subdomain · ${esc(name)}</div>${esc(cls.explain)}<div class="tip-osint">📜 ${esc(meta.issuer)}<br>📅 ${esc(meta.date)}<br>🔁 ${meta.count} certs</div><div class="tip-source">source: crt.sh</div></div></div>`;}).join('')}</div>${sorted.length>100?`<div style="font-size:12px;color:var(--c-hint);margin-top:10px;font-family:var(--font-mono)">Showing 100 of ${sorted.length} subdomains</div>`:''}`;
}

function renderStack(){
  const wrap=el('stack-wrap'); if(!wrap) return;
  if(!D.stack.length){wrap.innerHTML='<div class="no-data">No technologies detected.</div>';return;}
  const groups={};
  for(const t of D.stack){if(!groups[t.category])groups[t.category]=[];groups[t.category].push(t);}
  wrap.innerHTML=Object.entries(groups).map(([cat,techs])=>`<div style="margin-bottom:16px"><div style="font-size:10px;font-family:var(--font-mono);letter-spacing:0.12em;text-transform:uppercase;color:var(--c-hint);margin-bottom:8px">${esc(cat)}</div><div style="display:flex;flex-wrap:wrap;gap:7px">${techs.map(t=>`<div class="has-tooltip" style="position:relative;display:inline-flex;align-items:center;gap:7px;padding:7px 12px;background:var(--c-surface);border-radius:8px;border:0.5px solid var(--c-border);font-size:13px;cursor:default"><span style="width:9px;height:9px;border-radius:50%;background:${esc(t.color)};flex-shrink:0;display:inline-block"></span><span style="font-weight:500;color:var(--c-text)">${esc(t.name)}</span><div class="tip"><div class="tip-title">${esc(t.name)} · ${esc(t.category)}</div>Detected via: <span style="font-family:var(--font-mono);font-size:11px;opacity:0.85">${esc(t.evidence)}</span><div class="tip-source">source: HTTP headers + page source</div></div></div>`).join('')}</div></div>`).join('');
}

function renderHeaders(){
  const wrap=el('headers-wrap'),secWrap=el('sec-headers-wrap'); if(!wrap) return;
  if(!Object.keys(D.headers).length){wrap.innerHTML='<div class="error-box">Could not retrieve headers — API may be rate-limited. Try again in a moment.</div>';if(secWrap)secWrap.innerHTML='';return;}
  wrap.innerHTML=`<table class="meta-table">${Object.entries(D.headers).map(([k,v])=>row(k,`<span style="font-family:var(--font-mono);font-size:11px;word-break:break-all">${esc(v.slice(0,200))}</span>`)).join('')}</table>`;
  if(secWrap)secWrap.innerHTML=`<table class="meta-table">${SEC_HEADERS.map(h=>row(h,D.headers[h]?pill('present','pill-ok'):pill('missing','pill-err'))).join('')}</table>`;
}

function renderFindings(){
  const list=el('findings-list'),empty=el('findings-empty'); if(!list) return;
  if(!D.findings.length){list.innerHTML='';show('findings-empty');return;}
  hide('findings-empty');
  const sc={HIGH:'sev-high',MEDIUM:'sev-med',LOW:'sev-low'};
  list.innerHTML=D.findings.map(f=>`<div class="finding-item"><div class="finding-sev ${sc[f.sev]||''}">${esc(f.sev)}</div><div><div class="finding-title">${esc(f.title)}</div><div class="finding-detail">${esc(f.detail)}</div></div></div>`).join('');
  const b=el('badge-findings'); if(b) b.textContent=D.findings.length;
}

// ─── Tab navigation ───────────────────────────────────────────────────────────
function switchTab(name,tabEl){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el('tab-'+name)?.classList.add('active'); tabEl?.classList.add('active');
  document.querySelectorAll('.module-item').forEach(m=>m.classList.remove('active'));
  el('mod-'+name)?.classList.add('active');
}
function gotoTab(name){
  if(el('state-results')?.style.display==='none') return;
  const names=['dashboard','overview','dns','ssl','web','lang','headers','attack','findings'];
  switchTab(name,document.querySelectorAll('.tab')[names.indexOf(name)]||null);
}
document.addEventListener('DOMContentLoaded',()=>{el('domainInput')?.addEventListener('keydown',e=>{if(e.key==='Enter')startScan();});});
