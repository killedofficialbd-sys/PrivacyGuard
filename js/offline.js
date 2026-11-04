const $ = (s, r=document) => r.querySelector(s);
const VERSION = '3.1.0';
let installPrompt = null;

function classifyError(error){
  const code=String(error?.code||'').toLowerCase();
  const message=String(error?.message||'').toLowerCase();
  const status=Number(error?.status||error?.statusCode||0);
  if(status===404||code.includes('not-found')||message.includes('404'))return 'PG-404';
  if(status===429||message.includes('rate limit')||message.includes('ограничил частоту'))return 'PG-SRC-429';
  if(code.includes('permission-denied')||code.includes('unauthorized'))return 'PG-FS-403';
  if(status===403)return 'PG-SRC-403';
  if(status===401||code.includes('unauthenticated')||code.startsWith('auth/'))return 'PG-AUTH-401';
  if(!navigator.onLine||code.includes('network')||code==='unavailable'||message.includes('failed to fetch'))return 'PG-NET-001';
  if(code.includes('deadline-exceeded')||message.includes('timeout')||message.includes('вовремя'))return 'PG-SRC-408';
  if(message.includes('cors')||message.includes('недоступен из браузера')||(status>=500&&status<=599))return 'PG-SRC-502';
  return 'PG-APP-500';
}
window.PGErrorCode=classifyError;

function toast(message,error=false){
  let host=$('#toastContainer');
  if(!host){host=document.createElement('div');host.id='toastContainer';host.className='toast-container';document.body.append(host);}
  const node=document.createElement('div');node.className=`toast${error?' error':''}`;node.textContent=message;host.append(node);setTimeout(()=>node.remove(),5000);
}

function mountNetworkBar(){
  if($('#pgNetworkBar'))return;
  const bar=document.createElement('div');bar.id='pgNetworkBar';bar.className='pg-network-bar';bar.hidden=true;bar.setAttribute('role','status');bar.setAttribute('aria-live','polite');
  bar.innerHTML='<span class="pg-network-icon">⌁</span><span><b>Офлайн-режим</b><small>Локальные инструменты доступны. Внешние API и синхронизация Firebase ждут соединения.</small></span><button type="button" id="pgOfflineRetry">Повторить</button>';
  const top=$('.topbar');if(top)top.insertAdjacentElement('afterend',bar);else document.body.prepend(bar);
  $('#pgOfflineRetry').addEventListener('click',()=>testConnection());
}
function updateNetwork(){
  mountNetworkBar();const offline=!navigator.onLine;$('#pgNetworkBar').hidden=!offline;
  const connection=$('#pgConnectionText');if(connection)connection.textContent=offline?'Нет соединения':'Браузер сообщает: онлайн';
  const worker=$('#pgWorkerText');if(worker)worker.textContent=('serviceWorker'in navigator)?(navigator.serviceWorker.controller?'Активен':'Зарегистрирован / ожидает контроль'):'Не поддерживается';
  const storage=$('#pgStorageText');if(storage){let persisted=false;try{persisted=localStorage.getItem('privacyguard:trusted-offline-cache')==='true';}catch{}storage.textContent=persisted?'Постоянный Firestore-кэш включён':'Только кэш оболочки приложения';}
  window.dispatchEvent(new CustomEvent('pg:network',{detail:{online:!offline}}));
}
async function testConnection(){
  const result=$('#pgConnectionResult');if(result)result.textContent='Проверяем соединение с текущим хостом…';
  if(!navigator.onLine){if(result)result.textContent='PG-NET-001 · Браузер сообщает, что соединение отсутствует.';return false;}
  try{
    const url=new URL('manifest.json',document.baseURI);url.searchParams.set('pg_probe',String(Date.now()));
    const response=await fetch(url,{cache:'no-store'});
    if(!response.ok)throw Object.assign(new Error(`HTTP ${response.status}`),{status:response.status});
    if(result)result.textContent='Соединение с хостом работает. Это не проверяет доступность Firebase и каждого стороннего API.';
    updateNetwork();return true;
  }catch(error){if(result)result.textContent=`${classifyError(error)} · ${error.message||'Хост не ответил.'}`;return false;}
}
window.PGTestConnection=testConnection;

function restoreTrustedCacheControls(){
  let enabled=false;try{enabled=localStorage.getItem('privacyguard:trusted-offline-cache')==='true';}catch{}
  const authToggle=$('#pgTrustedDeviceAuth'),settingsToggle=$('#pgOfflineCacheToggle');
  if(authToggle){authToggle.checked=enabled;authToggle.addEventListener('change',()=>setTrustedCache(authToggle.checked,settingsToggle));}
  if(settingsToggle){settingsToggle.checked=enabled;settingsToggle.addEventListener('change',()=>setTrustedCache(settingsToggle.checked,authToggle));}
}
function setTrustedCache(next,other){
  try{localStorage.setItem('privacyguard:trusted-offline-cache',String(!!next));}catch{}
  if(other)other.checked=!!next;
  toast(next?'Офлайн-кэш включится после полного перезапуска. Только для личного устройства.':'Офлайн-кэш отключится после перезапуска приложения.');
  updateNetwork();
}
async function requestPersistentStorage(){
  const result=$('#pgConnectionResult');
  if(!navigator.storage?.persist){if(result)result.textContent='Браузер не поддерживает StorageManager.persist().';return;}
  try{
    const granted=await navigator.storage.persist();
    const estimate=await navigator.storage.estimate?.();
    const used=estimate?.usage!=null?`${(estimate.usage/1024/1024).toFixed(1)} МБ используется`:'объём неизвестен';
    const quota=estimate?.quota!=null?`${(estimate.quota/1024/1024).toFixed(0)} МБ доступно`:'лимит неизвестен';
    if(result)result.textContent=`${granted?'Хранилище защищено от автоматического удаления':'Браузер не предоставил постоянное хранилище'}. ${used}; ${quota}. Это не создаёт резервную копию.`;
  }catch(error){if(result)result.textContent=`${classifyError(error)} · ${error.message}`;}
}
async function clearShellCache(){
  if(!confirm('Очистить только кэш оболочки PrivacyGuard? Сохранённые данные Firebase не удаляются.'))return;
  try{
    const keys=await caches.keys();
    await Promise.all(keys.filter(k=>k.startsWith('privacyguard-shell-')).map(k=>caches.delete(k)));
    const result=$('#pgConnectionResult');if(result)result.textContent='Кэш оболочки очищен. Firebase и пользовательские данные не затронуты. Перезагрузи страницу онлайн для повторной загрузки.';
    toast('Кэш оболочки PrivacyGuard очищен.');
  }catch(error){toast(`${classifyError(error)} · Не удалось очистить кэш.`,true);}
}

window.addEventListener('online',updateNetwork);
window.addEventListener('offline',updateNetwork);
window.addEventListener('error',event=>{
  const code=classifyError(event.error||new Error(event.message||'Unhandled error'));
  console.error('PrivacyGuard runtime error',code,event.error||event.message);
  if(event.error?.name!=='AbortError')toast(`${code} · Внутренняя ошибка. Подробности доступны в консоли браузера.`,true);
});
window.addEventListener('unhandledrejection',event=>{
  const code=classifyError(event.reason);console.error('PrivacyGuard async error',code,event.reason);
  toast(`${code} · Не удалось завершить действие.`,true);
});

document.addEventListener('click',e=>{
  const action=e.target.closest('[data-pg-action]');if(!action)return;
  switch(action.dataset.pgAction){
    case 'reload-for-cache': location.reload(); break;
    case 'connection-test': testConnection(); break;
    case 'persist-storage': requestPersistentStorage(); break;
    case 'clear-shell-cache': clearShellCache(); break;
    case 'install-app': installApp(); break;
  }
});
window.addEventListener('beforeinstallprompt',event=>{
  event.preventDefault();installPrompt=event;
  const button=$('#pgInstallApp');if(button)button.hidden=false;
});
window.addEventListener('appinstalled',()=>{installPrompt=null;const button=$('#pgInstallApp');if(button)button.hidden=true;toast('PrivacyGuard установлен.');});
async function installApp(){
  if(!installPrompt){toast('Для установки открой меню браузера и выбери «Добавить на главный экран». На iPhone — «Поделиться» → «На экран Домой».');return;}
  try{await installPrompt.prompt();const choice=await installPrompt.userChoice;if(choice?.outcome==='accepted')toast('Запрос установки принят.');else toast('Установка отменена.');}catch(error){toast(`${classifyError(error)} · Не удалось открыть установку.`,true);}finally{installPrompt=null;const button=$('#pgInstallApp');if(button)button.hidden=true;}
}
if('serviceWorker'in navigator){
  navigator.serviceWorker.addEventListener('controllerchange',()=>toast('Офлайн-оболочка PrivacyGuard обновлена.'));
  window.addEventListener('load',async()=>{
    if(location.protocol==='file:')return;
    try{
      const registration=await navigator.serviceWorker.register('./service-worker.js');
      registration.addEventListener('updatefound',()=>{const worker=registration.installing;if(!worker)return;worker.addEventListener('statechange',()=>{if(worker.state==='installed'&&navigator.serviceWorker.controller)toast('Доступно обновление PrivacyGuard. Перезагрузи страницу.');});});
    }catch(error){console.warn('Service Worker registration failed:',error);toast(`${classifyError(error)} · PWA-кэш не активирован.`,true);}
  });
}
function toastReady(){restoreTrustedCacheControls();updateNetwork();}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',toastReady,{once:true});else toastReady();
