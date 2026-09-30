import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { LockKeyhole, Upload, Download, LogOut, ShieldCheck, FileKey2 } from 'lucide-react';
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
async function request(path:string, options:RequestInit={}) {
  const r = await fetch(API+path, {...options, credentials:'include'});
  if (!r.ok) { let msg='Request failed'; try { msg=(await r.json()).detail || msg; } catch {} throw new Error(msg); }
  if (r.status===204) return null;
  return r.json();
}

function App(){
  const [user,setUser]=useState<any>(null); const [vaultKey,setVaultKey]=useState<CryptoKey|null>(null);
  const [files,setFiles]=useState<any[]>([]); const [names,setNames]=useState<Record<number,string>>({});
  const [mode,setMode]=useState<'login'|'register'>('login'); const [msg,setMsg]=useState('');
  useEffect(()=>{request('/api/auth/me').then(setUser).catch(()=>{});},[]);
  useEffect(()=>{ if(user) loadFiles(); },[user]);
  async function loadFiles(){ try{setFiles(await request('/api/files'));}catch{} }
  useEffect(()=>{ if(!vaultKey) {setNames({});return;} Promise.all(files.map(async f=>[f.id,await decryptName(f,vaultKey)] as const)).then(x=>setNames(Object.fromEntries(x))).catch(()=>setMsg('Could not decrypt file metadata.')); },[files,vaultKey]);
  async function auth(e:any){e.preventDefault(); setMsg(''); const f=new FormData(e.currentTarget); const username=String(f.get('username')); const password=String(f.get('password')); const vault=String(f.get('vault'));
    try { if(mode==='register'){const created=await createVault(vault); const u=await request('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,...created.material})}); setUser(u);setVaultKey(created.vaultKey);} else {const u=await request('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})}); const m=await request('/api/vault/material'); setVaultKey(await unlockVault(vault,m));setUser(u);} } catch(err:any){setMsg(err.message==='The operation failed for an operation-specific reason'?'Login succeeded, but the vault passphrase is incorrect.':err.message);} }
  async function unlock(e:any){e.preventDefault();setMsg('');try{const f=new FormData(e.currentTarget);const m=await request('/api/vault/material');setVaultKey(await unlockVault(String(f.get('vault')),m));}catch{setMsg('Incorrect vault passphrase.');}}
  async function upload(e:any){const file=e.target.files?.[0]; e.target.value=''; if(!file||!vaultKey)return;setMsg('Encrypting locally…');try{const x=await encryptFile(file,vaultKey);const fd=new FormData();fd.append('blob',new Blob([x.ciphertext]),'ciphertext.enc');for(const k of ['encrypted_filename','filename_iv','file_iv','wrapped_dek','dek_wrap_iv'] as const)fd.append(k,x[k]);await request('/api/files',{method:'POST',body:fd});setMsg('Encrypted locally and stored as ciphertext.');await loadFiles();}catch(err:any){setMsg(err.message);}}
  async function download(row:any){if(!vaultKey)return;setMsg('Downloading ciphertext…');try{const r=await fetch(API+`/api/files/${row.id}/blob`,{credentials:'include'});if(!r.ok)throw new Error('Download failed');const plain=await decryptBlob(row,vaultKey,await r.arrayBuffer());const url=URL.createObjectURL(new Blob([plain]));const a=document.createElement('a');a.href=url;a.download=names[row.id]||'decrypted-file';a.click();URL.revokeObjectURL(url);setMsg('Decrypted locally.');}catch{setMsg('Integrity/decryption failed. The ciphertext or key material may be invalid.');}}
  async function logout(){await request('/api/auth/logout',{method:'POST'});setUser(null);setVaultKey(null);setFiles([]);setMsg('');}
  if(!user)return <main className="auth-shell"><section className="brand"><div className="logo"><LockKeyhole/> CIPHERDROP</div><h1>Your files. Your keys.</h1><p>Client-side encrypted storage designed so the server stores ciphertext, not your plaintext files.</p><div className="trust"><ShieldCheck/> AES-256-GCM client encryption</div></section><section className="card auth"><h2>{mode==='login'?'Welcome back':'Create your vault'}</h2><p>{mode==='login'?'Authenticate, then unlock your local vault key.':'Your vault master key is generated in this browser.'}</p><form onSubmit={auth}><label>Username<input name="username" required minLength={3}/></label><label>Account password<input name="password" type="password" required minLength={10}/></label><label>Vault passphrase<input name="vault" type="password" required minLength={10}/><small>Never sent to CipherDrop.</small></label><button>{mode==='login'?'Sign in & unlock':'Create encrypted vault'}</button></form>{msg&&<div className="message">{msg}</div>}<button className="link" onClick={()=>setMode(mode==='login'?'register':'login')}>{mode==='login'?'Need an account? Create one':'Already registered? Sign in'}</button></section></main>;
  return <div className="app"><aside><div className="logo"><LockKeyhole/> CIPHERDROP</div><nav><b>◈ Vault</b><span>⇄ Shared</span><span>◷ Activity</span><span>🛡 Security</span></nav><div className="user">@{user.username}<button className="ghost" onClick={logout}><LogOut size={16}/> Logout</button></div></aside><main className="content"><header><div><span className="eyebrow">PRIVATE VAULT</span><h1>Encrypted files</h1></div><div className={'status '+(vaultKey?'ok':'locked')}><ShieldCheck size={17}/>{vaultKey?'Vault unlocked':'Vault locked'}</div></header>{!vaultKey?<section className="card unlock"><FileKey2 size={38}/><h2>Unlock your vault</h2><p>Your encryption key is not retained after a page reload.</p><form onSubmit={unlock}><input name="vault" type="password" placeholder="Vault passphrase" required/><button>Unlock</button></form></section>:<><label className="drop"><Upload size={30}/><b>Drop a file into your encrypted vault</b><span>Encryption happens in this browser before upload.</span><input type="file" onChange={upload}/></label><section className="files"><div className="files-head"><h2>Recent files</h2><span>{files.length} encrypted object{files.length===1?'':'s'}</span></div>{files.length===0?<div className="empty">No files yet. Upload something to test the encryption pipeline.</div>:files.map(f=><article key={f.id}><div className="file-icon"><LockKeyhole/></div><div className="file-info"><b>{names[f.id]||'Decrypting filename…'}</b><span>{(f.size_bytes/1024).toFixed(1)} KB ciphertext · AES-256-GCM</span></div><button className="download" onClick={()=>download(f)}><Download size={17}/> Decrypt & Download</button></article>)}</section></>}{msg&&<div className="toast">{msg}</div>}</main></div>;
}
createRoot(document.getElementById('root')!).render(<App/>);
