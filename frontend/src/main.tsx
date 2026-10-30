import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { LockKeyhole, Upload, Download, LogOut, ShieldCheck, FileKey2, Share2, X, Trash2, RefreshCw, Users, UserMinus, Link2, Activity, Monitor, ShieldAlert } from 'lucide-react';
import './styles.css';

const API = '';
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKEK(passphrase: string, salt: Uint8Array, iterations: number) {
  const material = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', hash:'SHA-256', salt, iterations}, material, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function createVault(passphrase: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 600000;
  const kek = await deriveKEK(passphrase, salt, iterations);
  const vaultKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  const vaultKey = await crypto.subtle.importKey('raw', vaultKeyRaw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  const wrapped = await crypto.subtle.encrypt({name:'AES-GCM', iv}, kek, vaultKeyRaw);
  return {vaultKey, material:{vault_salt:b64(salt), vault_wrap_iv:b64(iv), wrapped_vault_key:b64(wrapped), kdf_iterations:iterations}};
}
async function unlockVault(passphrase: string, m: any) {
  const kek = await deriveKEK(passphrase, unb64(m.vault_salt), m.kdf_iterations);
  const raw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(m.vault_wrap_iv)}, kek, unb64(m.wrapped_vault_key));
  return crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
async function encryptFile(file: File, vaultKey: CryptoKey) {
  const dekRaw = crypto.getRandomValues(new Uint8Array(32));
  const dek = await crypto.subtle.importKey('raw', dekRaw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv:fileIv}, dek, await file.arrayBuffer());
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedDek = await crypto.subtle.encrypt({name:'AES-GCM', iv:wrapIv}, vaultKey, dekRaw);
  const nameIv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedName = await crypto.subtle.encrypt({name:'AES-GCM', iv:nameIv}, vaultKey, enc.encode(file.name));
  return {ciphertext, file_iv:b64(fileIv), wrapped_dek:b64(wrappedDek), dek_wrap_iv:b64(wrapIv), encrypted_filename:b64(encryptedName), filename_iv:b64(nameIv)};
}
async function decryptName(row:any, vaultKey:CryptoKey) {
  const raw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.filename_iv)}, vaultKey, unb64(row.encrypted_filename));
  return dec.decode(raw);
}
async function decryptBlob(row:any, vaultKey:CryptoKey, blob:ArrayBuffer) {
  const dekRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.dek_wrap_iv)}, vaultKey, unb64(row.wrapped_dek));
  const dek = await crypto.subtle.importKey('raw', dekRaw, {name:'AES-GCM'}, false, ['decrypt']);
  return crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.file_iv)}, dek, blob);
}

// Sharing uses the browser's Web Crypto implementation of ECDH P-256 + HKDF-SHA-256.
// The private sharing key is encrypted by the user's vault key before it is stored server-side.
async function createSharingProfile(vaultKey: CryptoKey) {
  const pair = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedPrivate = await crypto.subtle.encrypt({name:'AES-GCM', iv}, vaultKey, enc.encode(JSON.stringify(privateJwk)));
  return {privateKey: pair.privateKey, payload:{public_key_jwk:JSON.stringify(publicJwk), encrypted_private_key:b64(encryptedPrivate), private_key_iv:b64(iv)}};
}
async function unlockSharingPrivate(profile:any, vaultKey:CryptoKey) {
  const raw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(profile.private_key_iv)}, vaultKey, unb64(profile.encrypted_private_key));
  const jwk = JSON.parse(dec.decode(raw));
  return crypto.subtle.importKey('jwk', jwk, {name:'ECDH', namedCurve:'P-256'}, false, ['deriveBits']);
}
async function importSharingPublic(jwkText:string) {
  return crypto.subtle.importKey('jwk', JSON.parse(jwkText), {name:'ECDH', namedCurve:'P-256'}, false, []);
}
async function deriveShareKey(privateKey:CryptoKey, publicKey:CryptoKey, salt:Uint8Array) {
  const secret = await crypto.subtle.deriveBits({name:'ECDH', public:publicKey}, privateKey, 256);
  const hkdfKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt, info:enc.encode('CipherDrop file share v1')}, hkdfKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function buildShare(row:any, vaultKey:CryptoKey, senderPrivate:CryptoKey, recipientPublicJwk:string) {
  const dekRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.dek_wrap_iv)}, vaultKey, unb64(row.wrapped_dek));
  const filenameRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.filename_iv)}, vaultKey, unb64(row.encrypted_filename));
  const recipientPublic = await importSharingPublic(recipientPublicJwk);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const shareKey = await deriveShareKey(senderPrivate, recipientPublic, salt);
  const dekIv = crypto.getRandomValues(new Uint8Array(12));
  const filenameIv = crypto.getRandomValues(new Uint8Array(12));
  return {
    wrapped_dek:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv:dekIv}, shareKey, dekRaw)),
    dek_wrap_iv:b64(dekIv),
    encrypted_filename:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv:filenameIv}, shareKey, filenameRaw)),
    filename_iv:b64(filenameIv), hkdf_salt:b64(salt)
  };
}
async function buildReshare(row:any, recipientPrivate:CryptoKey, newRecipientPublicJwk:string) {
  const senderPublic = await importSharingPublic(row.sender_public_key_jwk);
  const currentShareKey = await deriveShareKey(recipientPrivate, senderPublic, unb64(row.hkdf_salt));
  const dekRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.dek_wrap_iv)}, currentShareKey, unb64(row.wrapped_dek));
  const filenameRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.filename_iv)}, currentShareKey, unb64(row.encrypted_filename));
  const recipientPublic = await importSharingPublic(newRecipientPublicJwk);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const newShareKey = await deriveShareKey(recipientPrivate, recipientPublic, salt);
  const dekIv = crypto.getRandomValues(new Uint8Array(12));
  const filenameIv = crypto.getRandomValues(new Uint8Array(12));
  return {
    wrapped_dek:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv:dekIv}, newShareKey, dekRaw)),
    dek_wrap_iv:b64(dekIv),
    encrypted_filename:b64(await crypto.subtle.encrypt({name:'AES-GCM', iv:filenameIv}, newShareKey, filenameRaw)),
    filename_iv:b64(filenameIv), hkdf_salt:b64(salt)
  };
}
function expirationFromForm(f:FormData){
  const mode=String(f.get('expiration')||'never');
  if(mode==='never')return null;
  if(mode==='custom'){const raw=String(f.get('custom_expiration')||'');return raw?new Date(raw).toISOString():null;}
  return new Date(Date.now()+Number(mode)*60*60*1000).toISOString();
}
function permissionText(row:any){
  const parts=['View']; if(row.can_download)parts.push('Download'); if(row.can_reshare)parts.push('Reshare'); return parts.join(' + ');
}
function expiryText(value:any){return value?`Expires ${new Date(value).toLocaleString()}`:'No expiration';}

async function decryptSharedMetadata(row:any, recipientPrivate:CryptoKey) {
  const senderPublic = await importSharingPublic(row.sender_public_key_jwk);
  const shareKey = await deriveShareKey(recipientPrivate, senderPublic, unb64(row.hkdf_salt));
  const filenameRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.filename_iv)}, shareKey, unb64(row.encrypted_filename));
  return {name:dec.decode(filenameRaw), shareKey};
}
async function decryptSharedBlob(row:any, recipientPrivate:CryptoKey, blob:ArrayBuffer) {
  const senderPublic = await importSharingPublic(row.sender_public_key_jwk);
  const shareKey = await deriveShareKey(recipientPrivate, senderPublic, unb64(row.hkdf_salt));
  const dekRaw = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.dek_wrap_iv)}, shareKey, unb64(row.wrapped_dek));
  const dek = await crypto.subtle.importKey('raw', dekRaw, {name:'AES-GCM'}, false, ['decrypt']);
  return crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(row.file_iv)}, dek, blob);
}
async function request(path:string, options:RequestInit={}) {
  const r = await fetch(API+path, {...options, credentials:'include'});
  if (!r.ok) { let msg='Request failed'; try { msg=(await r.json()).detail || msg; } catch {} throw new Error(msg); }
  if (r.status===204) return null;
  return r.json();
}

function App(){
  const [user,setUser]=useState<any>(null); const [vaultKey,setVaultKey]=useState<CryptoKey|null>(null);
  const [sharingPrivate,setSharingPrivate]=useState<CryptoKey|null>(null);
  const [files,setFiles]=useState<any[]>([]); const [names,setNames]=useState<Record<number,string>>({});
  const [shared,setShared]=useState<any[]>([]); const [sharedNames,setSharedNames]=useState<Record<number,string>>({});
  const [view,setView]=useState<'vault'|'shared'|'activity'|'security'>('vault'); const [shareFile,setShareFile]=useState<any|null>(null);
  const [reshareFile,setReshareFile]=useState<any|null>(null); const [manageFile,setManageFile]=useState<any|null>(null);
  const [grants,setGrants]=useState<any[]>([]); const [expiryMode,setExpiryMode]=useState('never');
  const [sessions,setSessions]=useState<any[]>([]); const [activity,setActivity]=useState<any[]>([]);
  const [auditResult,setAuditResult]=useState<any>(null); const [linkFile,setLinkFile]=useState<any|null>(null);
  const [linkList,setLinkList]=useState<any[]>([]); const [createdLink,setCreatedLink]=useState('');
  const [mode,setMode]=useState<'login'|'register'>('login'); const [msg,setMsg]=useState('');
  useEffect(()=>{request('/api/auth/me').then(setUser).catch(()=>{});},[]);
  useEffect(()=>{ if(user) {loadFiles();loadShared();} },[user]);
  async function loadSecurity(){try{setSessions(await request('/api/security/sessions'));}catch(e:any){setMsg(e.message);}}
  async function loadActivity(){try{setActivity(await request('/api/security/activity'));}catch(e:any){setMsg(e.message);}}
  async function verifyAudit(){try{setAuditResult(await request('/api/security/audit/verify'));}catch(e:any){setMsg(e.message);}}
  async function revokeSession(id:number){try{await request(`/api/security/sessions/${id}`,{method:'DELETE'});await loadSecurity();}catch(e:any){setMsg(e.message);}}
  async function revokeOthers(){try{const r=await request('/api/security/sessions/revoke-others',{method:'POST'});setMsg(`Revoked ${r.revoked} other session(s).`);await loadSecurity();}catch(e:any){setMsg(e.message);}}
  async function openLinks(f:any){setLinkFile(f);setCreatedLink('');try{setLinkList(await request(`/api/files/${f.id}/links`));}catch(e:any){setMsg(e.message);}}
  async function revokeLink(id:number){if(!linkFile)return;try{await request(`/api/files/${linkFile.id}/links/${id}`,{method:'DELETE'});setLinkList(await request(`/api/files/${linkFile.id}/links`));setMsg('Link revoked.');}catch(e:any){setMsg(e.message);}}
  async function createSecureLink(e:any){e.preventDefault();if(!linkFile||!vaultKey)return;const f=new FormData(e.currentTarget);try{const secret=crypto.getRandomValues(new Uint8Array(32));const key=await crypto.subtle.importKey('raw',secret,{name:'AES-GCM'},false,['encrypt','decrypt']);const dek=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(linkFile.dek_wrap_iv)},vaultKey,unb64(linkFile.wrapped_dek));const name=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(linkFile.filename_iv)},vaultKey,unb64(linkFile.encrypted_filename));const iv=crypto.getRandomValues(new Uint8Array(12));const niv=crypto.getRandomValues(new Uint8Array(12));const data={wrapped_dek:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,dek)),dek_wrap_iv:b64(iv),encrypted_filename:b64(await crypto.subtle.encrypt({name:'AES-GCM',iv:niv},key,name)),filename_iv:b64(niv),expires_at:expirationFromForm(f),max_downloads:Number(f.get('limit')||1)};const r=await request(`/api/files/${linkFile.id}/links`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});setCreatedLink(`${location.origin}/#link=${encodeURIComponent(r.token)}.${b64(secret).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}`);setLinkList(await request(`/api/files/${linkFile.id}/links`));setMsg('Encrypted link created. Copy it now: secret is not stored by the server.');}catch(err:any){setMsg(err.message);}}
  async function loadFiles(){ try{setFiles(await request('/api/files'));}catch{} }
  async function loadShared(){ try{setShared(await request('/api/shared'));}catch{} }
  async function loadGrants(file:any){setManageFile(file);try{setGrants(await request(`/api/files/${file.id}/shares`));}catch(err:any){setMsg(err.message);}}
  useEffect(()=>{ if(!vaultKey) {setNames({});return;} Promise.all(files.map(async f=>[f.id,await decryptName(f,vaultKey)] as const)).then(x=>setNames(Object.fromEntries(x))).catch(()=>setMsg('Could not decrypt file metadata.')); },[files,vaultKey]);
  useEffect(()=>{ if(!sharingPrivate){setSharedNames({});return;} Promise.all(shared.map(async s=>[s.id,(await decryptSharedMetadata(s,sharingPrivate)).name] as const)).then(x=>setSharedNames(Object.fromEntries(x))).catch(()=>setMsg('Could not decrypt one or more shared filenames.')); },[shared,sharingPrivate]);

  async function initializeSharing(vault:CryptoKey){const profile=await request('/api/sharing/profile');if(profile.configured){setSharingPrivate(await unlockSharingPrivate(profile,vault));return;}const created=await createSharingProfile(vault);await request('/api/sharing/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(created.payload)});setSharingPrivate(created.privateKey);}
  async function auth(e:any){e.preventDefault();setMsg('');const f=new FormData(e.currentTarget);const username=String(f.get('username'));const password=String(f.get('password'));const vault=String(f.get('vault'));try{if(mode==='register'){const created=await createVault(vault);const u=await request('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,...created.material})});setUser(u);setVaultKey(created.vaultKey);await initializeSharing(created.vaultKey);}else{const u=await request('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});const m=await request('/api/vault/material');const key=await unlockVault(vault,m);setVaultKey(key);setUser(u);await initializeSharing(key);}}catch(err:any){setMsg(err.message==='The operation failed for an operation-specific reason'?'Login succeeded, but the vault passphrase is incorrect.':err.message);}}
  async function unlock(e:any){e.preventDefault();setMsg('');try{const f=new FormData(e.currentTarget);const m=await request('/api/vault/material');const key=await unlockVault(String(f.get('vault')),m);setVaultKey(key);await initializeSharing(key);}catch{setMsg('Incorrect vault passphrase.');}}
  async function upload(e:any){const file=e.target.files?.[0];e.target.value='';if(!file||!vaultKey)return;setMsg('Encrypting locally…');try{const x=await encryptFile(file,vaultKey);const fd=new FormData();fd.append('blob',new Blob([x.ciphertext]),'ciphertext.enc');for(const k of ['encrypted_filename','filename_iv','file_iv','wrapped_dek','dek_wrap_iv'] as const)fd.append(k,x[k]);await request('/api/files',{method:'POST',body:fd});setMsg('Encrypted locally and stored as ciphertext.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  async function download(row:any){if(!vaultKey)return;setMsg('Downloading ciphertext…');try{const r=await fetch(API+`/api/files/${row.id}/blob`,{credentials:'include'});if(!r.ok)throw new Error('Download failed');const plain=await decryptBlob(row,vaultKey,await r.arrayBuffer());savePlain(plain,names[row.id]||'decrypted-file');setMsg('Decrypted locally.');}catch{setMsg('Integrity/decryption failed. The ciphertext or key material may be invalid.');}}
  async function replaceFile(row:any,file:File|undefined){if(!file||!vaultKey)return;const currentName=names[row.id]||'this file';if(!confirm(`Replace ${currentName}? Existing shares will be revoked and the replacement will use fresh encryption keys.`))return;setMsg('Encrypting replacement locally…');try{const x=await encryptFile(file,vaultKey);const fd=new FormData();fd.append('blob',new Blob([x.ciphertext]),'ciphertext.enc');for(const k of ['encrypted_filename','filename_iv','file_iv','wrapped_dek','dek_wrap_iv'] as const)fd.append(k,x[k]);await request(`/api/files/${row.id}`,{method:'PUT',body:fd});setMsg('File replaced securely. Existing shares were revoked.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  async function deleteFile(row:any){const name=names[row.id]||'this encrypted file';if(!confirm(`Delete ${name}? This permanently removes the encrypted object and revokes all existing shares.`))return;setMsg('Deleting encrypted file…');try{await request(`/api/files/${row.id}`,{method:'DELETE'});setMsg('Encrypted file deleted and shares revoked.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  function savePlain(plain:ArrayBuffer,name:string){const url=URL.createObjectURL(new Blob([plain]));const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
  async function submitShare(e:any){e.preventDefault();if(!shareFile||!vaultKey||!sharingPrivate)return;const f=new FormData(e.currentTarget);const recipient=String(f.get('recipient')).trim().toLowerCase();setMsg('Creating recipient-specific encrypted key…');try{const target=await request(`/api/users/${encodeURIComponent(recipient)}/public-key`);const crypto=await buildShare(shareFile,vaultKey,sharingPrivate,target.public_key_jwk);await request(`/api/files/${shareFile.id}/shares`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipient_username:recipient,...crypto,can_view:true,can_download:f.get('download')==='on',can_reshare:f.get('reshare')==='on',expires_at:expirationFromForm(f)})});setShareFile(null);setExpiryMode('never');setMsg(`Shared securely with @${recipient}.`);}catch(err:any){setMsg(err.message);}}
  async function submitReshare(e:any){e.preventDefault();if(!reshareFile||!sharingPrivate)return;const f=new FormData(e.currentTarget);const recipient=String(f.get('recipient')).trim().toLowerCase();setMsg('Re-wrapping file key for recipient…');try{const target=await request(`/api/users/${encodeURIComponent(recipient)}/public-key`);const crypto=await buildReshare(reshareFile,sharingPrivate,target.public_key_jwk);await request(`/api/shared/${reshareFile.id}/reshare`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipient_username:recipient,...crypto,can_view:true,can_download:f.get('download')==='on',can_reshare:f.get('reshare')==='on',expires_at:expirationFromForm(f)})});setReshareFile(null);setExpiryMode('never');setMsg(`Re-shared securely with @${recipient}.`);}catch(err:any){setMsg(err.message);}}
  async function revokeGrant(grant:any){if(!manageFile||!confirm(`Revoke @${grant.recipient_username}'s access? Any access re-shared through this grant will also be revoked.`))return;try{await request(`/api/files/${manageFile.id}/shares/${grant.id}`,{method:'DELETE'});setMsg(`Access revoked for @${grant.recipient_username}.`);await loadGrants(manageFile);await loadShared();}catch(err:any){setMsg(err.message);}}
  async function downloadShared(row:any){if(!sharingPrivate)return;setMsg('Downloading shared ciphertext…');try{const r=await fetch(API+`/api/shared/${row.id}/blob`,{credentials:'include'});if(!r.ok)throw new Error('Download failed');const plain=await decryptSharedBlob(row,sharingPrivate,await r.arrayBuffer());savePlain(plain,sharedNames[row.id]||'shared-file');setMsg('Shared file decrypted locally.');}catch{setMsg('Shared-file integrity/decryption failed or download permission is unavailable.');}}
  async function logout(){await request('/api/auth/logout',{method:'POST'});setUser(null);setVaultKey(null);setSharingPrivate(null);setFiles([]);setShared([]);setMsg('');}

  const permissionFields=<><div className="permissions"><label><input type="checkbox" checked readOnly/> View listing</label><label><input name="download" type="checkbox" defaultChecked/> Download</label><label><input name="reshare" type="checkbox"/> Reshare</label></div><label>Expiration<select name="expiration" value={expiryMode} onChange={e=>setExpiryMode(e.target.value)}><option value="never">Never</option><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option><option value="custom">Custom</option></select></label>{expiryMode==='custom'&&<label>Custom expiration<input name="custom_expiration" type="datetime-local" required/></label>}</>;

  const linkFragment=location.hash.startsWith('#link=')?location.hash.slice(6):'';
  if(linkFragment)return <PublicLink fragment={linkFragment}/>;

  if(!user)return <main className="auth-shell"><section className="brand"><div className="logo"><LockKeyhole/> CIPHERDROP</div><h1>Your files. Your keys.</h1><p>Client-side encrypted storage designed so the server stores ciphertext, not your plaintext files.</p><div className="trust"><ShieldCheck/> AES-256-GCM client encryption</div></section><section className="card auth"><h2>{mode==='login'?'Welcome back':'Create your vault'}</h2><p>{mode==='login'?'Authenticate, then unlock your local vault key.':'Your vault master key is generated in this browser.'}</p><form onSubmit={auth}><label>Username<input name="username" required minLength={3}/></label><label>Account password<input name="password" type="password" required minLength={10}/></label><label>Vault passphrase<input name="vault" type="password" required minLength={10}/><small>Never sent to CipherDrop.</small></label><button>{mode==='login'?'Sign in & unlock':'Create encrypted vault'}</button></form>{msg&&<div className="message">{msg}</div>}<button className="link" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Need an account? Create one':'Already registered? Sign in'}</button></section></main>;

  return <div className="app"><aside><div className="logo"><LockKeyhole/> CIPHERDROP</div><nav><button className={view==='vault'?'active':''} onClick={()=>setView('vault')}>◈ Vault</button><button className={view==='shared'?'active':''} onClick={()=>{setView('shared');loadShared();}}>⇄ Shared</button><button className={view==='activity'?'active':''} onClick={()=>{setView('activity');loadActivity();}}>◷ Activity</button><button className={view==='security'?'active':''} onClick={()=>{setView('security');loadSecurity();verifyAudit();}}>🛡 Security</button></nav><div className="user">@{user.username}<button className="ghost" onClick={logout}><LogOut size={16}/> Logout</button></div></aside><main className="content"><header><div><span className="eyebrow">{view==='vault'?'PRIVATE VAULT':view==='shared'?'ENCRYPTED SHARING':view==='activity'?'SECURITY ACTIVITY':'SECURITY CENTER'}</span><h1>{view==='vault'?'Encrypted files':view==='shared'?'Shared with me':view==='activity'?'Activity timeline':'Sessions & audit'}</h1></div><div className={'status '+(vaultKey?'ok':'locked')}><ShieldCheck size={17}/>{vaultKey&&sharingPrivate?'Keys unlocked':'Vault locked'}</div></header>{!vaultKey?<section className="card unlock"><FileKey2 size={38}/><h2>Unlock your vault</h2><p>Your encryption keys are not retained after a page reload.</p><form onSubmit={unlock}><input name="vault" type="password" placeholder="Vault passphrase" required/><button>Unlock</button></form></section>:view==='vault'?<><label className="drop"><Upload size={30}/><b>Drop a file into your encrypted vault</b><span>Encryption happens in this browser before upload.</span><input type="file" onChange={upload}/></label><section className="files"><div className="files-head"><h2>Recent files</h2><span>{files.length} encrypted object{files.length===1?'':'s'}</span></div>{files.length===0?<div className="empty">No files yet. Upload something to test the encryption pipeline.</div>:files.map(f=><article key={f.id}><div className="file-icon"><LockKeyhole/></div><div className="file-info"><b>{names[f.id]||'Decrypting filename…'}</b><span>{(f.size_bytes/1024).toFixed(1)} KB ciphertext · AES-256-GCM</span></div><button className="download" onClick={()=>{setExpiryMode('never');setShareFile(f)}}><Share2 size={17}/> Share</button><button className="download" onClick={()=>loadGrants(f)}><Users size={17}/> Manage</button><button className="download" onClick={()=>openLinks(f)}><Link2 size={17}/> Links</button><label className="download replace"><RefreshCw size={17}/> Replace<input type="file" onChange={e=>{const file=e.target.files?.[0];e.target.value='';replaceFile(f,file);}}/></label><button className="download" onClick={()=>download(f)}><Download size={17}/> Decrypt & Download</button><button className="trash" title={`Delete ${names[f.id]||'file'}`} aria-label={`Delete ${names[f.id]||'file'}`} onClick={()=>deleteFile(f)}><Trash2 size={18}/></button></article>)}</section></>:view==='activity'?<section className="files shared-list"><div className="files-head"><h2>Recent security events</h2><button className="download" onClick={loadActivity}>Refresh</button></div>{activity.map(a=><article key={a.id}><Activity size={18}/><div className="file-info"><b>{a.event_type}</b><span>{new Date(a.created_at).toLocaleString()} · {a.result} · {a.resource_id||'account'}</span></div></article>)}</section>:view==='security'?<section className="files shared-list"><div className="files-head"><h2>Active sessions</h2><button className="download" onClick={revokeOthers}>Revoke all other sessions</button></div>{sessions.map(x=><article key={x.id}><Monitor size={20}/><div className="file-info"><b>{x.current?'Current session':'Other session'}</b><span>{x.user_agent||'Unknown device'} · {x.ip_address||'Unknown IP'} · expires {new Date(x.expires_at).toLocaleString()}</span></div>{!x.current&&<button className="revoke" onClick={()=>revokeSession(x.id)}>Revoke</button>}</article>)}<div className="files-head"><h2>Audit chain</h2><button className="download" onClick={verifyAudit}>Verify chain</button></div><div className="empty">{auditResult?(auditResult.valid?`Verified ${auditResult.checked} events`:`Integrity check FAILED at event ${auditResult.failed_event_id}`):'Checking…'}</div></section>:<section className="files shared-list"><div className="files-head"><h2>Files shared with you</h2><span>{shared.length} active grant{shared.length===1?'':'s'}</span></div>{shared.length===0?<div className="empty">Nothing has been shared with this account yet.</div>:shared.map(s=><article key={s.id}><div className="file-icon"><Share2/></div><div className="file-info"><b>{sharedNames[s.id]||'Decrypting filename…'}</b><span>From @{s.grantor_username} · {permissionText(s)} · {expiryText(s.expires_at)}</span></div>{s.can_reshare&&<button className="download" onClick={()=>{setExpiryMode('never');setReshareFile(s)}}><Share2 size={17}/> Reshare</button>}{s.can_download?<button className="download" onClick={()=>downloadShared(s)}><Download size={17}/> Decrypt & Download</button>:<span className="permission-denied">Download disabled</span>}</article>)}</section>}{msg&&<div className="toast">{msg}</div>}
  {shareFile&&<div className="modal-backdrop"><section className="card modal"><button className="modal-x" onClick={()=>setShareFile(null)}><X/></button><Share2 size={34}/><h2>Share encrypted file</h2><p><b>{names[shareFile.id]}</b></p><p className="muted">Recipient-specific key material is created in this browser. Expiration and permissions are enforced server-side.</p><form onSubmit={submitShare}><label>Recipient username<input name="recipient" placeholder="bob" required minLength={3}/></label>{permissionFields}<button>Share securely</button></form></section></div>}
  {reshareFile&&<div className="modal-backdrop"><section className="card modal"><button className="modal-x" onClick={()=>setReshareFile(null)}><X/></button><Share2 size={34}/><h2>Reshare encrypted file</h2><p><b>{sharedNames[reshareFile.id]}</b></p><p className="muted">Your browser unwraps the existing DEK and re-wraps it for the new recipient. A child grant cannot outlive the grant you received.</p><form onSubmit={submitReshare}><label>Recipient username<input name="recipient" placeholder="charlie" required minLength={3}/></label>{permissionFields}<button>Reshare securely</button></form></section></div>}
  {linkFile&&<div className="modal-backdrop"><section className="card modal manage-modal"><button className="modal-x" onClick={()=>setLinkFile(null)}><X/></button><Link2 size={34}/><h2>Secure download links</h2><p><b>{names[linkFile.id]}</b></p><p className="muted">The link fragment holds the decryption secret. Anyone with the complete URL can download until the limit or expiration.</p><form onSubmit={createSecureLink}><label>Expiration<select name="expiration" value={expiryMode} onChange={e=>setExpiryMode(e.target.value)}><option value="never">Never</option><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option><option value="custom">Custom</option></select></label>{expiryMode==='custom'&&<label>Custom expiration<input name="custom_expiration" type="datetime-local" required/></label>}<label>Maximum downloads<input name="limit" type="number" min="1" max="100" defaultValue="1" required/></label><button>Generate encrypted link</button></form>{createdLink&&<div className="grant"><div><b>Copy this URL now</b><input readOnly value={createdLink} onFocus={e=>e.currentTarget.select()}/></div><button className="download" onClick={()=>navigator.clipboard.writeText(createdLink)}>Copy</button></div>}<div className="grant-list">{linkList.map(l=><div className="grant" key={l.id}><div><b>Link #{l.id}</b><span>{l.download_count}/{l.max_downloads} downloads · {expiryText(l.expires_at)}</span></div><button className="revoke" onClick={()=>revokeLink(l.id)}>Revoke</button></div>)}</div></section></div>}
  {manageFile&&<div className="modal-backdrop"><section className="card modal manage-modal"><button className="modal-x" onClick={()=>setManageFile(null)}><X/></button><Users size={34}/><h2>Manage access</h2><p><b>{names[manageFile.id]}</b></p><p className="muted">Revoking a grant also revokes any downstream access created through that grant.</p><div className="grant-list">{grants.length===0?<div className="empty">No active or expired grants for this file.</div>:grants.map(g=><div className="grant" key={g.id}><div><b>@{g.recipient_username}</b><span>{permissionText(g)} · {g.expired?'Expired':expiryText(g.expires_at)}{!g.is_direct?` · via @${g.grantor_username}`:''}</span></div><button className="revoke" onClick={()=>revokeGrant(g)}><UserMinus size={16}/> Revoke</button></div>)}</div></section></div>}
  </main></div>;
}
createRoot(document.getElementById('root')!).render(<App/>);

function savePublicFile(plain:ArrayBuffer,name:string){const url=URL.createObjectURL(new Blob([plain]));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function PublicLink({fragment}:{fragment:string}){
  const [state,setState]=useState('Loading encrypted link…');
  const [meta,setMeta]=useState<any>(null);
  const [filename,setFilename]=useState('encrypted-file');
  const [token,secretB64]=fragment.split('.');
  useEffect(()=>{(async()=>{try{if(!token||!secretB64)throw new Error('Invalid link');const m=await request(`/api/public/links/${encodeURIComponent(token)}`);const raw=unb64(secretB64.replace(/-/g,'+').replace(/_/g,'/'));const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);const name=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(m.filename_iv)},key,unb64(m.encrypted_filename));setFilename(dec.decode(name));setMeta(m);setState('Ready to decrypt in this browser.');}catch(e:any){setState(e.message);}})();},[fragment]);
  async function getFile(){try{setState('Downloading ciphertext…');const r=await fetch(`/api/public/links/${encodeURIComponent(token)}/download`,{method:'POST'});if(!r.ok)throw new Error('Link expired, revoked, or download limit reached');const raw=unb64(secretB64.replace(/-/g,'+').replace(/_/g,'/'));const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);const dekRaw=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(meta.dek_wrap_iv)},key,unb64(meta.wrapped_dek));const dek=await crypto.subtle.importKey('raw',dekRaw,{name:'AES-GCM'},false,['decrypt']);const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(meta.file_iv)},dek,await r.arrayBuffer());savePublicFile(plain,filename);setState('Downloaded and decrypted locally.');}catch(e:any){setState(e.message);}}
  return <main className="auth-shell"><section className="brand"><div className="logo"><LockKeyhole/> CIPHERDROP</div><h1>Secure file delivery.</h1><p>The file is decrypted in your browser using a secret in this link, not on the server.</p></section><section className="card auth"><h2>Encrypted download</h2><p>{filename}</p><p>{state}</p><button disabled={!meta} onClick={getFile}>Decrypt & Download</button></section></main>;
}
