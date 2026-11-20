const CSRF = document.querySelector('meta[name="csrf-token"]').content;
const $ = id => document.getElementById(id);
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let keyId = 1;
let latestDiscovery = null;
let lastToken = '';
const ALL_FIELDS=['vendor_id','vendor_name','phone','email','bank_account','payment_status'];
let firstPermissionLoad=true;
async function adminGet(url){const r=await fetch(url,{credentials:'same-origin'});return await r.json()}
async function adminPost(url,data){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},credentials:'same-origin',body:JSON.stringify(data)});return {code:r.status, data:await r.json()}}
function chip(value){let kind=['bank_account','payment_status'].includes(value)?'sensitive':'safe';return `<span class="chip ${kind}">${escapeHTML(value)}</span>`}
async function refresh(){
 const d=await adminGet('/admin/api/state');
 if(d.error){location.href='/login';return}
 const k=d.integrations[0];
 if(!k){$('currentContract').textContent='No integration key exists';return}
 keyId=k.id;
 $('fieldCount').textContent=`${k.read_fields.length} / 6`;
 $('keyStatus').textContent=k.active?'ACTIVE':'REVOKED';
 $('keyExpiry').textContent=new Date(k.expires_at*1000).toLocaleString();
 $('auditCount').textContent=String(d.audit.length);
 if(firstPermissionLoad){
   $('permissionRows').innerHTML=ALL_FIELDS.map(f=>`<div class="permission-row"><span>${escapeHTML(f)}${['bank_account','payment_status'].includes(f)?' ⚠':''}</span><span><input type="checkbox" class="p-read" value="${escapeHTML(f)}" ${k.read_fields.includes(f)?'checked':''}></span><span><input type="checkbox" class="p-write" value="${escapeHTML(f)}" ${k.write_fields.includes(f)?'checked':''} ${f==='vendor_id'?'disabled':''}></span></div>`).join('');
   firstPermissionLoad=false;
 }

 $('currentContract').innerHTML=k.read_fields.map(chip).join('')+`<span class="chip">WRITE: ${k.write_fields.length} fields</span><span class="chip">SCOPE: ${escapeHTML(k.vendor_scope)}</span>`;
 $('vendors').innerHTML=d.vendors.map(v=>`<div class="record"><div><strong>${escapeHTML(v.vendor_name)}</strong><small>${escapeHTML(v.vendor_id)}</small></div><div><small>MASTER BANK</small><br/><span>${escapeHTML(v.bank_account)}</span></div></div>`).join('');
 $('auditBody').innerHTML=d.audit.length?d.audit.map(a=>`<tr><td>${escapeHTML(new Date(a.at_utc*1000).toLocaleString())}</td><td>${escapeHTML(a.method)}</td><td>${escapeHTML(a.record_id)}</td><td>${escapeHTML(a.requested)}</td><td class="${a.decision==='DENY'?'deny':'allow'}">${escapeHTML(a.decision)}</td><td>${escapeHTML(a.reason)}</td></tr>`).join(''):'<tr><td colspan="6">No access attempts recorded yet.</td></tr>';
}
$('runExperiment').onclick=async()=>{
 $('experimentResult').textContent='Running 6 experiments against the synthetic vendor fixtures...';
 try{
  let d=await adminGet('/admin/api/discover');
  if(d.error){$('experimentResult').textContent=d.error;return}
  latestDiscovery=d;
  $('experimentResult').innerHTML=`<div class="experiment-summary"><strong>Minimum working data:</strong> ${d.recommended_read_fields.map(escapeHTML).join(' · ')}<br/><small>${d.fixtures_tested} synthetic records used; write access is not needed for the tested task.</small></div><div class="experiment-grid">${d.trials.map(t=>`<div class="trial"><span>Remove <strong>${escapeHTML(t.removed_field)}</strong></span><strong class="${t.sync_still_passes?'allow':'deny'}">${t.sync_still_passes?'SYNC PASSES · REMOVE':'SYNC FAILS · KEEP'}</strong></div>`).join('')}</div><p class="fineprint">${escapeHTML(d.limits)}</p>`;
 }catch(e){$('experimentResult').textContent=String(e)}
};
$('applyContract').onclick=async()=>{
 if(!latestDiscovery){$('contractResult').textContent='Run the Necessity Experiment first.';return}
 if(!confirm('Apply discovered read fields and REMOVE all integration write permissions?'))return;
 let result=await adminPost('/admin/api/apply',{key_id:keyId,vendor_scope:$('scope').value,hours:Number($('hours').value)});
 $('contractResult').textContent=result.data.error??result.data.message;
 await refresh();
};
$('saveManual').onclick=async()=>{
 const read_fields=[...document.querySelectorAll('.p-read:checked')].map(x=>x.value);
 const write_fields=[...document.querySelectorAll('.p-write:checked')].map(x=>x.value);
 if(write_fields.some(f=>['bank_account','payment_status'].includes(f))&&!$('sensitiveAck').checked){
  $('manualResult').textContent='Tick the high-risk confirmation before granting financial write access.';return;
 }
 if(!confirm(`Apply manual permissions? READ: ${read_fields.join(', ')||'NONE'}; WRITE: ${write_fields.join(', ')||'NONE'}`))return;
 const result=await adminPost('/admin/api/manual',{key_id:keyId,read_fields,write_fields,vendor_scope:$('scope').value,hours:Number($('hours').value),acknowledge_sensitive:$('sensitiveAck').checked});
 $('manualResult').textContent=result.data.error??result.data.message;
 await refresh();
};
$('rotateKey').onclick=async()=>{
 if(!confirm('Issue a NEW integration token? Old API tokens will stop working immediately.'))return;
 const result=await adminPost('/admin/api/rotate',{key_id:keyId,hours:Number($('hours').value)});
 if(result.code!==200){$('rotationOutput').textContent=result.data.error??'Rotation failed';return}
 $('rotationOutput').innerHTML=`<strong>NEW TOKEN (copy now; shown once):</strong><br/><code>${escapeHTML(result.data.token)}</code><br/><small>Old token is invalid. This is a synthetic local demo credential.</small>`;
 $('token').value=result.data.token;
 await refresh();
};
$('revokeKey').onclick=async()=>{
 if(!confirm('Revoke this integration credential? All further API requests will be denied.'))return;
 const result=await adminPost('/admin/api/revoke',{key_id:keyId});
 $('contractResult').textContent=result.data.revoked?'Credential revoked; retest in the Playground.':JSON.stringify(result.data);
 await refresh();
};
async function apiRequest(kind){
 const token=$('token').value.trim();
 if(!token){$('apiResponse').textContent='Paste the generated synthetic token above first.';return}
 let url='/api/vendors/V-0412',method='GET',body=null;
 if(kind==='contact')url+='?fields=vendor_id,vendor_name,phone';
 if(kind==='bank')url+='?fields=vendor_id,vendor_name,bank_account';
 if(kind==='write'){method='PATCH';body={bank_account:'****9083'}};
 if(kind==='other')url='/api/vendors/V-0208?fields=vendor_id,phone';
 const options={method,headers:{Authorization:'Bearer '+token}};
 if(body){options.headers['Content-Type']='application/json';options.body=JSON.stringify(body)}
 try{
  let r=await fetch(url,options);
  let payload=await r.json();
  $('httpStatus').textContent=`${r.status} ${r.ok?'SUCCESS':'DENIED / ERROR'}`;
  $('httpStatus').className=r.ok?'allow':'deny';
  $('apiResponse').textContent=JSON.stringify({request:`${method} ${url}`,result:payload},null,2);
  await refresh();
 }catch(e){$('apiResponse').textContent=String(e)}
}
$('normalSync').onclick=()=>apiRequest('contact');
$('sensitiveRead').onclick=()=>apiRequest('bank');
$('bankUpdate').onclick=()=>apiRequest('write');
$('scopeTest').onclick=()=>apiRequest('other');
$('refresh').onclick=refresh;
$('logout').onclick=async()=>{await fetch('/admin/api/logout',{method:'POST',headers:{'X-CSRF-Token':CSRF}});location.href='/login'};
refresh();
