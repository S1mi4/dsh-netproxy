import { parseProxyServer } from '../lib/sysproxy.js';
let bad = 0;
const t = (label, v, expectNull = false) => { const r = parseProxyServer(v); if ((r === null) !== expectNull) bad += 1; console.log((r !== null ? 'ok  ' : 'ok(∅)') + '  ' + label, '=>', JSON.stringify(r)); };
t('single', '127.0.0.1:7890');
t('per-proto', 'http=127.0.0.1:81;https=proxy.corp:443;ftp=10.0.0.1:21');
t('socks-only', 'socks=127.0.0.1:1080');
t('empty', '', true);
t('bracket-ipv6', '[::1]:8080');
t('domain-single', 'proxy.example.com:3128');
t('https-only', 'https=gw.corp:8080');
const perProto = parseProxyServer('http=127.0.0.1:81;https=proxy.corp:443;ftp=10.0.0.1:21');
if (!perProto || perProto.host !== 'proxy.corp' || perProto.port !== 443) { bad += 1; console.log('FAIL https entry preferred'); }
else console.log('ok  https entry preferred');
const socks = parseProxyServer('socks=127.0.0.1:1080');
if (!socks || !/^socks5:\/\//.test(socks.url)) { bad += 1; console.log('FAIL socks url'); }
else console.log('ok  socks -> socks5 url');
console.log(bad === 0 ? '\nSYSPROXY PARSE PASS' : `\nSYSPROXY PARSE FAIL (${bad})`);
process.exit(bad === 0 ? 0 : 1);
