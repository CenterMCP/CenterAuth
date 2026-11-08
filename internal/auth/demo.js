'use strict';
const status=document.getElementById('status'),result=document.getElementById('result');
const buttons=[...document.querySelectorAll('button')];
const resource=location.origin+'/mcp',redirect=location.origin+'/demo/callback';
let session=JSON.parse(sessionStorage.getItem('centerauth.session')||'null'),busy=false,id=0;
function message(text,error=false){status.textContent=text;status.dataset.error=String(error);}
function save(){if(session)sessionStorage.setItem('centerauth.session',JSON.stringify(session));else sessionStorage.removeItem('centerauth.session');controls();}
function controls(){for(const button of buttons)button.disabled=busy||(button.id!=='connect'&&!session);}
function random(){const bytes=crypto.getRandomValues(new Uint8Array(32));return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');}
async function jsonFetch(url,options){const response=await fetch(url,options);const text=await response.text();const data=text?JSON.parse(text):{};if(!response.ok)throw new Error(data.error_description||data.error||'Request failed: '+response.status);return data;}
async function token(body){return jsonFetch('/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body)});}
async function mcp(method,params){
 const response=await fetch('/mcp',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/json, text/event-stream',Authorization:'Bearer '+session.access_token},body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params})});
 const text=await response.text();let data;
 if(response.headers.get('content-type')?.includes('text/event-stream')){const line=text.split('\n').find(line=>line.startsWith('data:'));if(!line)throw new Error('No MCP result');data=JSON.parse(line.slice(5));}else data=JSON.parse(text);
 if(!response.ok||data.error)throw new Error(data.error?.message||data.error_description||'MCP request failed: '+response.status);
 if(data.result?.isError)throw new Error(data.result.content?.[0]?.text||'Tool failed');return data.result;
}
async function profile(){await mcp('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'CenterAuth playground',version:'0.1.0'}});const output=await mcp('tools/call',{name:'get_my_profile',arguments:{}});result.textContent=JSON.stringify(output.structuredContent,null,2);message('MCP validated this request and returned your SQLite profile.');}
async function action(fn){if(busy)return;busy=true;controls();try{await fn();}catch(error){message(error.message,true);}finally{busy=false;controls();}}
document.getElementById('connect').onclick=()=>action(async()=>{
 const client=await jsonFetch('/oauth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_name:'CenterAuth browser playground',redirect_uris:[redirect],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']})});
 const verifier=random(),state=random(),hash=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))),challenge=btoa(String.fromCharCode(...hash)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
 sessionStorage.setItem('centerauth.pending',JSON.stringify({client_id:client.client_id,verifier,state}));
 const params=new URLSearchParams({client_id:client.client_id,redirect_uri:redirect,response_type:'code',scope:'profile:read',resource,code_challenge:challenge,code_challenge_method:'S256',state});location.assign('/oauth/authorize?'+params);
});
document.getElementById('profile').onclick=()=>action(profile);
document.getElementById('refresh').onclick=()=>action(async()=>{const next=await token({grant_type:'refresh_token',client_id:session.client_id,refresh_token:session.refresh_token,resource});session={...next,client_id:session.client_id};save();await profile();});
document.getElementById('logout').onclick=()=>action(async()=>{await jsonFetch('/oauth/revoke',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:session.client_id,token:session.refresh_token})});session=null;save();result.textContent='No connected user.';message('Tokens revoked. Future requests with these tokens will be rejected.');});
controls();
if(location.pathname==='/demo/callback')action(async()=>{
 const query=new URLSearchParams(location.search),pending=JSON.parse(sessionStorage.getItem('centerauth.pending')||'null');
 history.replaceState({},'', '/demo');sessionStorage.removeItem('centerauth.pending');
 if(!pending||query.get('state')!==pending.state)throw new Error('OAuth state mismatch. Start a new connection.');
 if(query.has('error'))throw new Error('Authorization declined: '+query.get('error'));
 if(query.get('iss')!==location.origin)throw new Error('OAuth issuer mismatch.');
 const tokens=await token({grant_type:'authorization_code',client_id:pending.client_id,redirect_uri:redirect,code:query.get('code'),code_verifier:pending.verifier,resource});session={...tokens,client_id:pending.client_id};save();await profile();
});
