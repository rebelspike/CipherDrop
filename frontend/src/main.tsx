import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { LockKeyhole, Upload, Download, LogOut, ShieldCheck, FileKey2, Share2, X, Trash2, RefreshCw } from 'lucide-react';
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
  const [view,setView]=useState<'vault'|'shared'>('vault'); const [shareFile,setShareFile]=useState<any|null>(null);
  const [mode,setMode]=useState<'login'|'register'>('login'); const [msg,setMsg]=useState('');
  useEffect(()=>{request('/api/auth/me').then(setUser).catch(()=>{});},[]);
  useEffect(()=>{ if(user) {loadFiles();loadShared();} },[user]);
  async function loadFiles(){ try{setFiles(await request('/api/files'));}catch{} }
  async function loadShared(){ try{setShared(await request('/api/shared'));}catch{} }
  useEffect(()=>{ if(!vaultKey) {setNames({});return;} Promise.all(files.map(async f=>[f.id,await decryptName(f,vaultKey)] as const)).then(x=>setNames(Object.fromEntries(x))).catch(()=>setMsg('Could not decrypt file metadata.')); },[files,vaultKey]);
  useEffect(()=>{ if(!sharingPrivate){setSharedNames({});return;} Promise.all(shared.map(async s=>[s.id,(await decryptSharedMetadata(s,sharingPrivate)).name] as const)).then(x=>setSharedNames(Object.fromEntries(x))).catch(()=>setMsg('Could not decrypt one or more shared filenames.')); },[shared,sharingPrivate]);

  async function initializeSharing(vault:CryptoKey){
    const profile=await request('/api/sharing/profile');
    if(profile.configured){setSharingPrivate(await unlockSharingPrivate(profile,vault));return;}
    const created=await createSharingProfile(vault);
    await request('/api/sharing/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(created.payload)});
    setSharingPrivate(created.privateKey);
  }
  async function auth(e:any){e.preventDefault(); setMsg(''); const f=new FormData(e.currentTarget); const username=String(f.get('username')); const password=String(f.get('password')); const vault=String(f.get('vault'));
    try { if(mode==='register'){const created=await createVault(vault); const u=await request('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,...created.material})}); setUser(u);setVaultKey(created.vaultKey);await initializeSharing(created.vaultKey);} else {const u=await request('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})}); const m=await request('/api/vault/material'); const key=await unlockVault(vault,m);setVaultKey(key);setUser(u);await initializeSharing(key);} } catch(err:any){setMsg(err.message==='The operation failed for an operation-specific reason'?'Login succeeded, but the vault passphrase is incorrect.':err.message);} }
  async function unlock(e:any){e.preventDefault();setMsg('');try{const f=new FormData(e.currentTarget);const m=await request('/api/vault/material');const key=await unlockVault(String(f.get('vault')),m);setVaultKey(key);await initializeSharing(key);}catch{setMsg('Incorrect vault passphrase.');}}
  async function upload(e:any){const file=e.target.files?.[0]; e.target.value=''; if(!file||!vaultKey)return;setMsg('Encrypting locally…');try{const x=await encryptFile(file,vaultKey);const fd=new FormData();fd.append('blob',new Blob([x.ciphertext]),'ciphertext.enc');for(const k of ['encrypted_filename','filename_iv','file_iv','wrapped_dek','dek_wrap_iv'] as const)fd.append(k,x[k]);await request('/api/files',{method:'POST',body:fd});setMsg('Encrypted locally and stored as ciphertext.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  async function download(row:any){if(!vaultKey)return;setMsg('Downloading ciphertext…');try{const r=await fetch(API+`/api/files/${row.id}/blob`,{credentials:'include'});if(!r.ok)throw new Error('Download failed');const plain=await decryptBlob(row,vaultKey,await r.arrayBuffer());savePlain(plain,names[row.id]||'decrypted-file');setMsg('Decrypted locally.');}catch{setMsg('Integrity/decryption failed. The ciphertext or key material may be invalid.');}}
  async function replaceFile(row:any,file:File|undefined){if(!file||!vaultKey)return;const currentName=names[row.id]||'this file';if(!confirm(`Replace ${currentName}? Existing shares will be revoked and the replacement will use fresh encryption keys.`))return;setMsg('Encrypting replacement locally…');try{const x=await encryptFile(file,vaultKey);const fd=new FormData();fd.append('blob',new Blob([x.ciphertext]),'ciphertext.enc');for(const k of ['encrypted_filename','filename_iv','file_iv','wrapped_dek','dek_wrap_iv'] as const)fd.append(k,x[k]);await request(`/api/files/${row.id}`,{method:'PUT',body:fd});setMsg('File replaced securely. Existing shares were revoked.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  async function deleteFile(row:any){const name=names[row.id]||'this encrypted file';if(!confirm(`Delete ${name}? This permanently removes the encrypted object and revokes all existing shares.`))return;setMsg('Deleting encrypted file…');try{await request(`/api/files/${row.id}`,{method:'DELETE'});setMsg('Encrypted file deleted and shares revoked.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  function savePlain(plain:ArrayBuffer,name:string){const url=URL.createObjectURL(new Blob([plain]));const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
  async function submitShare(e:any){e.preventDefault();if(!shareFile||!vaultKey||!sharingPrivate)return;const f=new FormData(e.currentTarget);const recipient=String(f.get('recipient')).trim().toLowerCase();setMsg('Creating recipient-specific encrypted key…');try{const target=await request(`/api/users/${encodeURIComponent(recipient)}/public-key`);const crypto=await buildShare(shareFile,vaultKey,sharingPrivate,target.public_key_jwk);await request(`/api/files/${shareFile.id}/shares`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipient_username:recipient,...crypto})});setShareFile(null);setMsg(`Shared securely with @${recipient}.`);}catch(err:any){setMsg(err.message);}}
  async function downloadShared(row:any){if(!sharingPrivate)return;setMsg('Downloading shared ciphertext…');try{const r=await fetch(API+`/api/shared/${row.id}/blob`,{credentials:'include'});if(!r.ok)throw new Error('Download failed');const plain=await decryptSharedBlob(row,sharingPrivate,await r.arrayBuffer());savePlain(plain,sharedNames[row.id]||'shared-file');setMsg('Shared file decrypted locally.');}catch{setMsg('Shared-file integrity/decryption failed.');}}
  async function logout(){await request('/api/auth/logout',{method:'POST'});setUser(null);setVaultKey(null);setSharingPrivate(null);setFiles([]);setShared([]);setMsg('');}

  if(!user)return <main className="auth-shell"><section className="brand"><div className="logo"><LockKeyhole/> CIPHERDROP</div><h1>Your files. Your keys.</h1><p>Client-side encrypted storage designed so the server stores ciphertext, not your plaintext files.</p><div className="trust"><ShieldCheck/> AES-256-GCM client encryption</div></section><section className="card auth"><h2>{mode==='login'?'Welcome back':'Create your vault'}</h2><p>{mode==='login'?'Authenticate, then unlock your local vault key.':'Your vault master key is generated in this browser.'}</p><form onSubmit={auth}><label>Username<input name="username" required minLength={3}/></label><label>Account password<input name="password" type="password" required minLength={10}/></label><label>Vault passphrase<input name="vault" type="password" required minLength={10}/><small>Never sent to CipherDrop.</small></label><button>{mode==='login'?'Sign in & unlock':'Create encrypted vault'}</button></form>{msg&&<div className="message">{msg}</div>}<button className="link" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Need an account? Create one':'Already registered? Sign in'}</button></section></main>;

  return <div className="app"><aside><div className="logo"><LockKeyhole/> CIPHERDROP</div><nav><button className={view==='vault'?'active':''} onClick={()=>setView('vault')}>◈ Vault</button><button className={view==='shared'?'active':''} onClick={()=>{setView('shared');loadShared();}}>⇄ Shared</button><span>◷ Activity</span><span>🛡 Security</span></nav><div className="user">@{user.username}<button className="ghost" onClick={logout}><LogOut size={16}/> Logout</button></div></aside><main className="content"><header><div><span className="eyebrow">{view==='vault'?'PRIVATE VAULT':'ENCRYPTED SHARING'}</span><h1>{view==='vault'?'Encrypted files':'Shared with me'}</h1></div><div className={'status '+(vaultKey?'ok':'locked')}><ShieldCheck size={17}/>{vaultKey&&sharingPrivate?'Keys unlocked':'Vault locked'}</div></header>{!vaultKey?<section className="card unlock"><FileKey2 size={38}/><h2>Unlock your vault</h2><p>Your encryption keys are not retained after a page reload.</p><form onSubmit={unlock}><input name="vault" type="password" placeholder="Vault passphrase" required/><button>Unlock</button></form></section>:view==='vault'?<><label className="drop"><Upload size={30}/><b>Drop a file into your encrypted vault</b><span>Encryption happens in this browser before upload.</span><input type="file" onChange={upload}/></label><section className="files"><div className="files-head"><h2>Recent files</h2><span>{files.length} encrypted object{files.length===1?'':'s'}</span></div>{files.length===0?<div className="empty">No files yet. Upload something to test the encryption pipeline.</div>:files.map(f=><article key={f.id}><div className="file-icon"><LockKeyhole/></div><div className="file-info"><b>{names[f.id]||'Decrypting filename…'}</b><span>{(f.size_bytes/1024).toFixed(1)} KB ciphertext · AES-256-GCM</span></div><button className="download" onClick={()=>setShareFile(f)}><Share2 size={17}/> Share</button><label className="download replace"><RefreshCw size={17}/> Replace<input type="file" onChange={e=>{const file=e.target.files?.[0];e.target.value='';replaceFile(f,file);}}/></label><button className="download" onClick={()=>download(f)}><Download size={17}/> Decrypt & Download</button><button className="trash" title={`Delete ${names[f.id]||'file'}`} aria-label={`Delete ${names[f.id]||'file'}`} onClick={()=>deleteFile(f)}><Trash2 size={18}/></button></article>)}</section></>:<section className="files shared-list"><div className="files-head"><h2>Files shared with you</h2><span>{shared.length} grant{shared.length===1?'':'s'}</span></div>{shared.length===0?<div className="empty">Nothing has been shared with this account yet.</div>:shared.map(s=><article key={s.id}><div className="file-icon"><Share2/></div><div className="file-info"><b>{sharedNames[s.id]||'Decrypting filename…'}</b><span>Shared by @{s.owner_username} · {(s.size_bytes/1024).toFixed(1)} KB ciphertext</span></div><button className="download" onClick={()=>downloadShared(s)}><Download size={17}/> Decrypt & Download</button></article>)}</section>}{msg&&<div className="toast">{msg}</div>}{shareFile&&<div className="modal-backdrop"><section className="card modal"><button className="modal-x" onClick={()=>setShareFile(null)}><X/></button><Share2 size={34}/><h2>Share encrypted file</h2><p><b>{names[shareFile.id]}</b></p><p className="muted">CipherDrop will create recipient-specific encrypted key material in this browser. The server never receives the raw file key.</p><form onSubmit={submitShare}><label>Recipient username<input name="recipient" placeholder="bob" required minLength={3}/></label><button>Share securely</button></form></section></div>}</main></div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
