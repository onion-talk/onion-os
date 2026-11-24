/* ==========================================================================
   OnionOS — Sober Obsidian & Cobalt Shield App & Symbolic Icon Registry
   Aligned with OnionTalk Onion Mesh Design System | Zero innerHTML | Zero Emojis
   ========================================================================== */

(() => {
  'use strict';

  const domParser = new DOMParser();
  let gradSeq = 0;

  const APP_SVGS = {
    oniontalk: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="ot-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#233042"/>
          <stop offset="52%" stop-color="#172130"/>
          <stop offset="100%" stop-color="#101722"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#ot-bg-__UID__)" stroke="#33455C" stroke-width="8"/>
      <path fill="#FFFFFF" d="M 264,96 C 344,96 408,160 408,240 C 408,320 344,384 264,384 C 238,384 214,377 192,366 C 163,384 128,393 118,394 C 114,394 112,390 114,386 C 124,365 136,342 134,326 C 124,300 118,271 118,240 C 118,160 184,96 264,96 Z"/>
      <path d="M 226,220 L 226,178 C 226,154 239,136 264,136 C 289,136 302,154 302,178 L 302,220" fill="none" stroke="#1B2838" stroke-width="22" stroke-linecap="round" stroke-linejoin="round"/>
      <path fill="#1B2838" d="M 212,216 C 212,208 218,202 226,202 L 302,202 C 310,202 316,208 316,216 L 316,264 C 316,294 292,316 264,316 C 236,316 212,294 212,264 Z"/>
      <circle cx="264" cy="245" r="9.5" fill="#5899FF"/>
      <path fill="#5899FF" d="M 259.5,245 L 256.5,272 C 256.5,275.5 259.5,278 264,278 C 268.5,278 271.5,275.5 271.5,272 L 268.5,245 Z"/>
    </svg>`,

    browser: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="br-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#221D36"/>
          <stop offset="55%" stop-color="#171427"/>
          <stop offset="100%" stop-color="#0F0E1B"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#br-bg-__UID__)" stroke="#372F54" stroke-width="8"/>
      <circle cx="256" cy="256" r="142" fill="#121020" stroke="#8B5CF6" stroke-opacity="0.72" stroke-width="12"/>
      <ellipse cx="256" cy="256" rx="74" ry="138" fill="none" stroke="#A78BFA" stroke-opacity="0.45" stroke-width="9"/>
      <line x1="116" y1="256" x2="396" y2="256" stroke="#A78BFA" stroke-opacity="0.45" stroke-width="9"/>
      <path d="M 256,138 A 118,118 0 0 1 256,374" fill="none" stroke="#F4F7FB" stroke-width="16" stroke-linecap="round"/>
      <path d="M 256,178 A 78,78 0 0 1 256,334" fill="none" stroke="#34D399" stroke-width="15" stroke-linecap="round"/>
      <circle cx="256" cy="256" r="21" fill="#F4F7FB"/>
    </svg>`,

    files: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="fl-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1E2B3E"/>
          <stop offset="55%" stop-color="#141E2C"/>
          <stop offset="100%" stop-color="#0E1520"/>
        </linearGradient>
        <linearGradient id="fl-front-__UID__" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stop-color="#275BA8"/>
          <stop offset="100%" stop-color="#193C73"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#fl-bg-__UID__)" stroke="#2F425B" stroke-width="8"/>
      <path d="M 96,154 C 96,134 112,118 132,118 H 214 L 246,150 H 380 C 400,150 416,166 416,186 V 364 C 416,384 400,400 380,400 H 132 C 112,400 96,384 96,364 Z" fill="#1D4D91"/>
      <rect x="122" y="166" width="268" height="72" rx="14" fill="#CBD5E1" fill-opacity="0.9"/>
      <rect x="96" y="196" width="320" height="204" rx="34" fill="url(#fl-front-__UID__)" stroke="#5899FF" stroke-opacity="0.42" stroke-width="6"/>
      <rect x="216" y="284" width="80" height="18" rx="9" fill="#E2E8F0"/>
    </svg>`,

    onionshare: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="os-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#142923"/>
          <stop offset="55%" stop-color="#0F1F1B"/>
          <stop offset="100%" stop-color="#0A1512"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#os-bg-__UID__)" stroke="#23473C" stroke-width="8"/>
      <circle cx="256" cy="248" r="132" fill="none" stroke="#34D399" stroke-opacity="0.28" stroke-width="10" stroke-dasharray="32 20"/>
      <path d="M 164,188 A 112,112 0 0 1 348,188" fill="none" stroke="#F4F7FB" stroke-width="15" stroke-linecap="round"/>
      <path d="M 196,218 A 72,72 0 0 1 316,218" fill="none" stroke="#34D399" stroke-width="15" stroke-linecap="round"/>
      <circle cx="256" cy="256" r="30" fill="#34D399"/>
      <path d="M 256,288 L 222,380 H 290 Z" fill="#F4F7FB"/>
      <circle cx="256" cy="256" r="11" fill="#0F1F1B"/>
    </svg>`,

    passwords: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="pw-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#212834"/>
          <stop offset="55%" stop-color="#161C26"/>
          <stop offset="100%" stop-color="#0E131B"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#pw-bg-__UID__)" stroke="#313D50" stroke-width="8"/>
      <circle cx="256" cy="256" r="128" fill="#111720" stroke="#475569" stroke-width="14"/>
      <circle cx="256" cy="256" r="88" fill="none" stroke="#F59E0B" stroke-width="14"/>
      <circle cx="256" cy="256" r="34" fill="#1C2533" stroke="#F59E0B" stroke-width="8"/>
      <line x1="256" y1="146" x2="256" y2="172" stroke="#94A3B8" stroke-width="10" stroke-linecap="round"/>
      <line x1="256" y1="340" x2="256" y2="366" stroke="#94A3B8" stroke-width="10" stroke-linecap="round"/>
      <line x1="146" y1="256" x2="172" y2="256" stroke="#94A3B8" stroke-width="10" stroke-linecap="round"/>
      <line x1="340" y1="256" x2="366" y2="256" stroke="#94A3B8" stroke-width="10" stroke-linecap="round"/>
      <circle cx="256" cy="256" r="10" fill="#F59E0B"/>
    </svg>`,

    editor: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="ed-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1E2836"/>
          <stop offset="100%" stop-color="#101620"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#ed-bg-__UID__)" stroke="#2E3D52" stroke-width="8"/>
      <rect x="110" y="96" width="292" height="320" rx="34" fill="#151C26" stroke="#33455C" stroke-width="8"/>
      <line x1="154" y1="168" x2="332" y2="168" stroke="#5899FF" stroke-width="14" stroke-linecap="round"/>
      <line x1="154" y1="220" x2="354" y2="220" stroke="#94A3B8" stroke-width="12" stroke-linecap="round"/>
      <line x1="154" y1="268" x2="314" y2="268" stroke="#94A3B8" stroke-width="12" stroke-linecap="round"/>
      <line x1="154" y1="316" x2="258" y2="316" stroke="#64748B" stroke-width="12" stroke-linecap="round"/>
      <g transform="translate(336, 326) rotate(38)">
        <rect x="-18" y="-76" width="36" height="110" rx="8" fill="#5899FF"/>
        <path d="M -18,34 L 0,68 L 18,34 Z" fill="#F4F7FB"/>
      </g>
    </svg>`,

    cleaner: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="cl-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#24202C"/>
          <stop offset="100%" stop-color="#11151E"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#cl-bg-__UID__)" stroke="#363246" stroke-width="8"/>
      <path d="M 248,98 L 128,148 V 246 C 128,330 178,388 248,412 C 318,388 368,330 368,246 V 148 Z" fill="#182230" stroke="#5899FF" stroke-width="12" stroke-linejoin="round"/>
      <path d="M 206,254 L 238,286 L 298,220" fill="none" stroke="#34D399" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

    network: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="nw-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1A293D"/>
          <stop offset="55%" stop-color="#111B29"/>
          <stop offset="100%" stop-color="#0B121C"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#nw-bg-__UID__)" stroke="#2A3E59" stroke-width="8"/>
      <circle cx="256" cy="256" r="138" fill="none" stroke="#5899FF" stroke-opacity="0.24" stroke-width="8"/>
      <line x1="146" y1="302" x2="248" y2="156" stroke="#5899FF" stroke-width="12" stroke-linecap="round"/>
      <line x1="248" y1="156" x2="368" y2="240" stroke="#34D399" stroke-width="12" stroke-linecap="round"/>
      <line x1="146" y1="302" x2="288" y2="346" stroke="#64748B" stroke-width="9"/>
      <line x1="288" y1="346" x2="368" y2="240" stroke="#64748B" stroke-width="9"/>
      <circle cx="146" cy="302" r="24" fill="#34D399" stroke="#0F1722" stroke-width="6"/>
      <circle cx="248" cy="156" r="26" fill="#5899FF" stroke="#0F1722" stroke-width="6"/>
      <circle cx="368" cy="240" r="24" fill="#34D399" stroke="#0F1722" stroke-width="6"/>
      <circle cx="288" cy="346" r="20" fill="#94A3B8" stroke="#0F1722" stroke-width="6"/>
    </svg>`,

    terminal: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="tm-bg-__UID__" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stop-color="#1B2330"/>
          <stop offset="100%" stop-color="#0E131B"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#tm-bg-__UID__)" stroke="#2C3A4E" stroke-width="8"/>
      <rect x="64" y="64" width="384" height="384" rx="76" fill="#0A0E14" stroke="#1E293B" stroke-width="6"/>
      <path d="M 132,182 L 210,242 L 132,302" fill="none" stroke="#34D399" stroke-width="26" stroke-linecap="round" stroke-linejoin="round"/>
      <line x1="236" y1="306" x2="336" y2="306" stroke="#5899FF" stroke-width="26" stroke-linecap="round"/>
    </svg>`,

    settings: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="st-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#1F2835"/>
          <stop offset="100%" stop-color="#111720"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#st-bg-__UID__)" stroke="#313E52" stroke-width="8"/>
      <g fill="#94A3B8">
        <rect x="232" y="92" width="48" height="328" rx="16"/>
        <rect x="92" y="232" width="328" height="48" rx="16"/>
        <rect x="232" y="92" width="48" height="328" rx="16" transform="rotate(45 256 256)"/>
        <rect x="232" y="92" width="48" height="328" rx="16" transform="rotate(-45 256 256)"/>
        <circle cx="256" cy="256" r="112"/>
      </g>
      <circle cx="256" cy="256" r="64" fill="#111720"/>
      <path d="M 202,260 H 232 L 245,230 L 266,286 L 281,252 H 310" fill="none" stroke="#5899FF" stroke-width="13" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`,

    relay: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
      <defs>
        <linearGradient id="rl-bg-__UID__" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#16293B"/>
          <stop offset="56%" stop-color="#101E2C"/>
          <stop offset="100%" stop-color="#0B141E"/>
        </linearGradient>
      </defs>
      <rect x="24" y="24" width="464" height="464" rx="112" fill="url(#rl-bg-__UID__)" stroke="#27435E" stroke-width="8"/>
      <polygon points="256,116 370,182 370,330 256,396 142,330 142,182" fill="#0D1824" stroke="#34D399" stroke-opacity="0.78" stroke-width="11" stroke-linejoin="round"/>
      <line x1="256" y1="116" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <line x1="370" y1="182" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <line x1="370" y1="330" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <line x1="256" y1="396" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <line x1="142" y1="330" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <line x1="142" y1="182" x2="256" y2="256" stroke="#5899FF" stroke-opacity="0.55" stroke-width="7"/>
      <circle cx="256" cy="116" r="18" fill="#34D399"/>
      <circle cx="370" cy="182" r="18" fill="#34D399"/>
      <circle cx="370" cy="330" r="18" fill="#34D399"/>
      <circle cx="256" cy="396" r="18" fill="#34D399"/>
      <circle cx="142" cy="330" r="18" fill="#34D399"/>
      <circle cx="142" cy="182" r="18" fill="#34D399"/>
      <circle cx="256" cy="256" r="40" fill="#19375E" stroke="#5899FF" stroke-width="9"/>
      <circle cx="256" cy="256" r="13" fill="#F4F7FB"/>
    </svg>`,
  };

  const SYMBOLIC_PATHS = {
    'relay-symbolic': '<polygon points="8,1.8 13.4,4.9 13.4,11.1 8,14.2 2.6,11.1 2.6,4.9" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linejoin="round"/><circle cx="8" cy="8" r="2.2" fill="currentColor"/><line x1="8" y1="1.8" x2="8" y2="5.8" stroke="currentColor" stroke-width="1.3"/><line x1="13.4" y1="4.9" x2="9.9" y2="6.9" stroke="currentColor" stroke-width="1.3"/><line x1="2.6" y1="4.9" x2="6.1" y2="6.9" stroke="currentColor" stroke-width="1.3"/>',
    relay: '<polygon points="8,1.8 13.4,4.9 13.4,11.1 8,14.2 2.6,11.1 2.6,4.9" fill="none" stroke="currentColor" stroke-width="1.55" stroke-linejoin="round"/><circle cx="8" cy="8" r="2.2" fill="currentColor"/><line x1="8" y1="1.8" x2="8" y2="5.8" stroke="currentColor" stroke-width="1.3"/><line x1="13.4" y1="4.9" x2="9.9" y2="6.9" stroke="currentColor" stroke-width="1.3"/><line x1="2.6" y1="4.9" x2="6.1" y2="6.9" stroke="currentColor" stroke-width="1.3"/>',
    minimize: '<path d="M4 11.5h8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    maximize: '<rect x="4" y="4" width="8" height="8" rx="1.2" fill="none" stroke="currentColor" stroke-width="1.75"/>',
    restore: '<path d="M5.5 6.5h6v6h-6z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M4.5 9.5v-5h5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
    close: '<path d="M4.5 4.5l7 7M11.5 4.5l-7 7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    search: '<circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.75"/><path d="M10.5 10.5L14 14" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/>',
    folder: '<path d="M1.8 4.2c0-.9.7-1.6 1.6-1.6h3.1l1.5 1.6h4.6c.9 0 1.6.7 1.6 1.6v6.2c0 .9-.7 1.6-1.6 1.6H3.4c-.9 0-1.6-.7-1.6-1.6z" fill="currentColor" fill-opacity="0.22" stroke="currentColor" stroke-width="1.5"/>',
    file: '<path d="M4 2h5.5L13 5.5V13c0 .6-.4 1-1 1H4c-.6 0-1-.4-1-1V3c0-.6.4-1 1-1z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 2v4h4" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    upload: '<path d="M8 11V3.5M5 6.2L8 3.2l3 3M3 13h10" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>',
    download: '<path d="M8 3v7.5M5 7.8l3 3 3-3M3 13h10" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>',
    plus: '<path d="M8 3.2v9.6M3.2 8h9.6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
    trash: '<path d="M3 4.5h10M6 4.5V3h4v1.5M4.5 4.5l.6 8.5h5.8l.6-8.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
    refresh: '<path d="M13.2 7A5.3 5.3 0 0 0 4 4.4L2.8 5.5M2.8 2.8v2.8h2.8M2.8 9A5.3 5.3 0 0 0 12 11.6l1.2-1.1M13.2 13.2v-2.8h-2.8" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round"/>',
    copy: '<rect x="6" y="6" width="7.5" height="7.5" rx="1.2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M3.5 10.5H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h6.5a1 1 0 0 1 1 1v.5" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    eye: '<path d="M1.8 8C3.2 5 5.4 3.5 8 3.5S12.8 5 14.2 8C12.8 11 10.6 12.5 8 12.5S3.2 11 1.8 8z" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="8" cy="8" r="2" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    'eye-off': '<path d="M2.2 2.2l11.6 11.6M4.2 4.6C2.9 5.6 2 6.8 1.5 8c1.4 3 3.7 4.5 6.5 4.5 1.2 0 2.3-.3 3.2-.8M6.8 3.6c.4-.1.8-.1 1.2-.1 2.8 0 5.1 1.5 6.5 4.5-.5 1-1.2 1.9-2 2.6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    shield: '<path d="M8 1.8L2.8 4v4c0 3.5 2.2 5.9 5.2 6.8 3-.9 5.2-3.3 5.2-6.8V4z" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linejoin="round"/><path d="M5.8 8.1l1.5 1.5 3-3" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round"/>',
    tor: '<circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.65"/><path d="M8 4.2a3.8 3.8 0 0 1 0 7.6" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round"/><circle cx="8" cy="8" r="1.4" fill="currentColor"/>',
    lock: '<rect x="3" y="7.2" width="10" height="6.8" rx="1.4" fill="none" stroke="currentColor" stroke-width="1.65"/><path d="M5.2 7.2V5a2.8 2.8 0 0 1 5.6 0v2.2" fill="none" stroke="currentColor" stroke-width="1.65"/>',
    unlock: '<rect x="3" y="7.2" width="10" height="6.8" rx="1.4" fill="none" stroke="currentColor" stroke-width="1.65"/><path d="M5.2 7.2V5a2.8 2.8 0 0 1 5.2-1.4" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round"/>',
    flame: '<path d="M8.2 1.8c1 2.2 3.8 3.4 3.8 6.9a4 4 0 0 1-8 0c0-1.8 1-3.2 2-4.2-.1 1.3.5 2.1 1.2 2.4-.4-1.8-.1-3.6 1-5.1z" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linejoin="round"/>',
    qr: '<rect x="2" y="2" width="4.5" height="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><rect x="9.5" y="2" width="4.5" height="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><rect x="2" y="9.5" width="4.5" height="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M9.5 9.5h2v2h-2zM12 12h2v2h-2zM12 9.5h2M9.5 12v2" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    key: '<circle cx="5.2" cy="10.5" r="2.8" fill="none" stroke="currentColor" stroke-width="1.65"/><path d="M7.3 8.4L13.5 2.2M11 4.7l2 2" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round"/>',
    globe: '<circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M2.2 8h11.6M8 2c1.8 1.8 2.7 3.8 2.7 6S9.8 12.2 8 14C6.2 12.2 5.3 10.2 5.3 8S6.2 3.8 8 2z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    sliders: '<path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="5.5" cy="4.5" r="1.6" fill="currentColor"/><circle cx="10.5" cy="8" r="1.6" fill="currentColor"/><circle cx="6.5" cy="11.5" r="1.6" fill="currentColor"/>',
    check: '<path d="M3 8.4l3.2 3.2L13 4.8" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round"/>',
    'chevron-right': '<path d="M6 3.5L10.5 8 6 12.5" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>',
    'chevron-left': '<path d="M10 3.5L5.5 8 10 12.5" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/>',
    wallpaper: '<rect x="2" y="3" width="12" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="5.4" cy="6.2" r="1.1" fill="currentColor"/><path d="M3 12l3.4-3.2 2.4 2.2 2.2-1.8 2 2.8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
    power: '<path d="M8 2.2v5.2M4.4 4.2a5.4 5.4 0 1 0 7.2 0" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/>',
    bell: '<path d="M8 2.4a3.8 3.8 0 0 0-3.8 3.8v2.6L2.8 10.6h10.4l-1.4-1.8V6.2A3.8 3.8 0 0 0 8 2.4zM6.6 12.4a1.5 1.5 0 0 0 2.8 0" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
    edit: '<path d="M10.8 2.6l2.6 2.6L5.6 13H3v-2.6z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>',
    share: '<circle cx="12" cy="3.5" r="1.8" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="4" cy="8" r="1.8" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12.5" r="1.8" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M5.6 7.1l4.8-2.7M5.6 8.9l4.8 2.7" stroke="currentColor" stroke-width="1.6"/>',
    terminal: '<rect x="2" y="3" width="12" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M4.8 6.2L7.2 8l-2.4 1.8M8.4 10h2.8" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
    cpu: '<rect x="4.2" y="4.2" width="7.6" height="7.6" rx="1.2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M6.5 2v2M9.5 2v2M6.5 12v2M9.5 12v2M2 6.5h2M2 9.5h2M12 6.5h2M12 9.5h2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>',
  };

  const ALLOWED_SVG_TAGS = new Set([
    'svg',
    'g',
    'path',
    'rect',
    'circle',
    'ellipse',
    'line',
    'polyline',
    'polygon',
    'defs',
    'lineargradient',
    'radialgradient',
    'stop',
    'clippath',
    'mask',
  ]);

  function sanitizeSvgTree(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    const forbiddenNodes = [];
    let current = root;
    while (current) {
      const tag = current.tagName.toLowerCase();
      if (!ALLOWED_SVG_TAGS.has(tag)) {
        forbiddenNodes.push(current);
      } else {
        for (const attr of Array.from(current.attributes)) {
          const attrName = attr.name.toLowerCase();
          const rawVal = attr.value.trim();
          const lowerVal = rawVal.toLowerCase();
          const isEvent = attrName.startsWith('on');
          const isXlinkHref =
            attrName === 'xlink:href' ||
            (attr.prefix && attr.prefix.toLowerCase() === 'xlink' && attr.localName && attr.localName.toLowerCase() === 'href');
          const isUnsafeHref =
            (attrName === 'href' || (attr.localName && attr.localName.toLowerCase() === 'href')) &&
            !rawVal.startsWith('#');
          const isUnsafeStyle =
            attrName === 'style' &&
            (lowerVal.includes('url(') ||
              lowerVal.includes('http:') ||
              lowerVal.includes('https:') ||
              lowerVal.includes('javascript:') ||
              lowerVal.includes('data:') ||
              lowerVal.includes('//'));
          const isExternalFuncIri =
            lowerVal.includes('url(') && !lowerVal.startsWith('url(#');

          if (isEvent || isXlinkHref || isUnsafeHref || isUnsafeStyle || isExternalFuncIri) {
            current.removeAttribute(attr.name);
          }
        }
      }
      current = walker.nextNode();
    }
    for (const bad of forbiddenNodes) {
      bad.remove();
    }
  }

  function parseSafeSvg(svgString, className = '') {
    const doc = domParser.parseFromString(String(svgString || ''), 'image/svg+xml');
    const root = doc.documentElement;
    if (!root || root.tagName.toLowerCase() !== 'svg' || doc.querySelector('parsererror')) {
      const fallback = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      fallback.setAttribute('viewBox', '0 0 16 16');
      if (className) fallback.setAttribute('class', className);
      return fallback;
    }
    const imported = document.importNode(root, true);
    sanitizeSvgTree(imported);
    imported.setAttribute('aria-hidden', 'true');
    imported.setAttribute('focusable', 'false');
    if (className) {
      imported.setAttribute('class', className);
    }
    return imported;
  }

  function createAppIcon(appId, sizePx = 48, className = 'adw-app-icon') {
    gradSeq += 1;
    const raw = (APP_SVGS[appId] || APP_SVGS.oniontalk).replaceAll('__UID__', String(gradSeq));
    const svg = parseSafeSvg(raw, className);
    svg.style.width = `${sizePx}px`;
    svg.style.height = `${sizePx}px`;
    return svg;
  }

  function createSymbolic(name, sizePx = 16, className = 'adw-sym-icon') {
    const inner = SYMBOLIC_PATHS[name] || SYMBOLIC_PATHS.shield;
    const raw = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">${inner}</svg>`;
    const svg = parseSafeSvg(raw, className);
    svg.style.width = `${sizePx}px`;
    svg.style.height = `${sizePx}px`;
    return svg;
  }

  window.OnionIcons = Object.freeze({
    createAppIcon,
    createSymbolic,
    parseSafeSvg,
  });
})();
