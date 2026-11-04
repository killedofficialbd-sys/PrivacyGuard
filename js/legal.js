import { auth, db } from './firebase.js';
import { onAuthStateChanged, signOut } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js';
import { doc, getDoc, getDocFromCache, getDocFromServer, setDoc, serverTimestamp } from 'https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js';

const TERMS_VERSION = '1.0';
const PRIVACY_VERSION = '1.0';
const AUP_VERSION = '1.0';
const APP_VERSION = '3.1.0';
const ACCEPTANCE_ID = `terms-${TERMS_VERSION}__privacy-${PRIVACY_VERSION}__aup-${AUP_VERSION}`;
const $ = (s, r=document) => r.querySelector(s);
const docs = {
  terms: {
    label:'Пользовательское соглашение', version:TERMS_VERSION,
    body:`<h2>1. Общие положения</h2><p>PrivacyGuard OSINT Suite — веб-инструмент для просмотра публичной технической информации, ручной проверки собственных цифровых активов и локальной работы с данными. Оператор сервиса: <b>Актив</b>, контакт: <b>killedofficialbd@gmail.com</b>. До заполнения этих данных владелец должен завершить настройку документа до публичного коммерческого запуска.</p><p>Создавая аккаунт или продолжая использование после явного подтверждения, пользователь принимает настоящие условия. Версия документа: ${TERMS_VERSION}; дата публикации: 4 ноября 2026 года.</p>
      <h2>2. Учётная запись</h2><ul><li>Пользователь обязан предоставлять корректные данные аккаунта и защищать доступ к своей учётной записи.</li><li>Действия, выполненные через аккаунт, считаются действиями пользователя до сообщения об утрате доступа.</li><li>Не передавай пароль от аккаунта и не сохраняй в формах сервиса пароли от сторонних сайтов.</li></ul>
      <h2>3. Допустимое использование</h2><p>Сервис предназначен для законного анализа открытых технических данных. Проверяй только собственные домены/IP или ресурсы, на исследование которых у тебя есть явное разрешение. Запрещены преследование людей, доксинг, незаконное получение персональных данных, обход контроля доступа, несанкционированное сканирование, эксплуатация уязвимостей и действия, нарушающие применимое право или условия сторонних источников.</p>
      <h2>4. Точность и ограничения результатов</h2><p>Данные поступают из сторонних публичных источников и могут быть неполными, устаревшими или недоступными. Отсутствие записи или ошибки запроса не доказывают безопасность актива. Результаты носят информационный характер и не являются юридическим, финансовым или профессиональным заключением.</p>
      <h2>5. Сторонние источники</h2><p>При запуске отдельных проверок введённый адрес, домен, IP, VIN, BIN или иной параметр может передаваться соответствующему внешнему источнику. Использование внешних источников регулируется также условиями и политиками этих поставщиков. Перед отправкой не вводи секреты, полные номера карт, CVV, приватные ключи и чужие персональные данные.</p>
      <h2>6. Доступность и изменения</h2><p>Сервис предоставляется в текущем состоянии. Отдельные функции могут временно быть недоступны из-за сети, CORS, ограничений источников, Firebase или работ по обновлению. Существенные изменения документов сопровождаются новой версией и повторным запросом подтверждения.</p>
      <h2>7. Ответственность</h2><p>В пределах, допускаемых применимым законодательством, оператор не гарантирует непрерывную доступность и абсолютную точность сторонних данных. Ничто в условиях не ограничивает права потребителя или ответственность, которые не могут быть ограничены законом.</p>
      <h2>8. Прекращение использования и контакты</h2><p>Пользователь может прекратить использование, выйти из аккаунта и запросить удаление учётной записи и связанных данных через настройки. Вопросы и обращения направляй по адресу: <b>killedofficialbd@gmail.com</b>.</p>
      <h2>9. Применимое право</h2><p>Применимое право и порядок разрешения споров должны быть заполнены оператором с учётом места его учреждения, аудитории сервиса и обязательных норм защиты прав пользователей.</b></p>`
  },
  privacy: {
    label:'Политика конфиденциальности', version:PRIVACY_VERSION,
    body:`<h2>1. Кто отвечает за обработку</h2><p>Оператор: <b>Актив</b>. Контакт по вопросам приватности: <b>killedofficialbd@gmail.com</b>. Не запускай публичную эксплуатацию до заполнения сведений об операторе, контактного адреса и сроков хранения.</p>
      <h2>2. Какие данные обрабатываются</h2><ul><li>Данные аккаунта: Firebase UID, email, имя профиля, фото профиля и техническая информация аутентификации.</li><li>Данные, которые пользователь сохраняет: история проверок и их краткие результаты, активы (домены/IP), заметки, проекты, отчёты, уведомления и настройки.</li><li>Журнал подтверждения документов: версии соглашения, факт отдельных отметок, язык, версия приложения и серверная временная метка. IP-адрес и пароль в этот журнал не записываются.</li><li>Технические сведения, которые могут автоматически обрабатываться Firebase, хостингом, браузером и выбранными внешними API, например IP-адрес запроса, время и сведения о браузере. Оператор должен сверить это с фактическими настройками поставщиков.</li></ul>
      <h2>3. Цели и правовые основания</h2><p>Данные аккаунта и сохранённое содержимое используются для предоставления запрошенных функций, входа, синхронизации, истории и поддержки сервиса; журнал версий — для фиксации принятия условий. Возможные основания по GDPR — исполнение договора/преддоговорные действия, законный интерес в безопасности и документировании действий, а для необязательных целей — отдельное согласие, если оно действительно требуется и используется. Оператор обязан самостоятельно подтвердить основания для каждого процесса.</p>
      <h2>4. Внешние источники и передача данных</h2><p>В зависимости от выбранной проверки данные запроса могут отправляться сервисам Firebase Authentication и Cloud Firestore, IPinfo, ipwho.is, Google Public DNS, RDAP, crt.sh, Shodan InternetDB, maclookup.app, Binlist, NHTSA vPIC, NVD/NIST и Have I Been Pwned. Если пользователь открывает внешнюю поисковую ссылку или профиль платформы, браузер переходит к соответствующему поставщику. У каждого поставщика собственные правила обработки и сроки хранения.</p><p>Для проверки пароля в Have I Been Pwned полный пароль и полный хеш остаются в браузере: запрос использует первые 5 символов SHA-1-хеша по модели k-анонимности, а сравнение оставшейся части выполняется локально. Не используй эту функцию для пароля, который должен оставаться полностью неизвестным третьим лицам, без оценки собственных требований безопасности.</p>
      <h2>5. Хранение и безопасность</h2><p>Профиль, история, активы, проекты и отчёты хранятся в Firestore в пространстве, привязанном к UID пользователя. Точные сроки хранения и резервного копирования. <b></b>. Пользователь может экспортировать доступные данные и инициировать удаление из интерфейса. Резервные копии поставщиков могут удаляться по отдельному циклу. Оператор должен опубликовать Firestore Rules и не использовать тестовые открытые правила.</p>
      <h2>6. Офлайн-кэш</h2><p>По умолчанию постоянный кэш Firestore выключен. Пользователь может добровольно включить его на личном доверенном устройстве. Такой кэш может сохраняться на устройстве после выхода из аккаунта; не включай его на общем устройстве. Service Worker кэширует файлы приложения, но не кэширует приватные ответы внешних API.</p>
      <h2>7. Права пользователя</h2><p>В зависимости от применимого права пользователь может запросить доступ, исправление, удаление, ограничение обработки, переносимость или возражать против обработки, а также подать жалобу в компетентный надзорный орган. Для обращения используй: <b>killedofficialbd@gmail.com</b>. Право отозвать согласие применяется к тем операциям, которые действительно основаны на согласии; принятие пользовательского соглашения и подтверждение ознакомления с уведомлением о конфиденциальности не следует смешивать с необязательным маркетинговым согласием.</p>
      <h2>8. Дети и особые категории данных</h2><p>Сервис не предназначен для загрузки специальных категорий персональных данных, паролей, платёжных секретов или данных третьих лиц без законного основания. Возрастные ограничения и порядок обработки обращений несовершеннолетних должны быть определены оператором до публикации.</p>
      <h2>9. Изменения</h2><p>При изменении целей, категорий данных, поставщиков или сроков хранения политика обновляется. Существенные изменения сопровождаются новой версией и повторным показом пользователю.</p>`
  },
  acceptable: {
    label:'Правила допустимого использования', version:AUP_VERSION,
    body:`<h2>Разрешено</h2><ul><li>Проверять собственные домены, серверы, IP-адреса и цифровые активы.</li><li>Проводить аудит по письменному разрешению владельца в рамках согласованного объёма.</li><li>Использовать публичные справочники, DNS, RDAP, сертификаты, CVE и локальные утилиты в законных целях.</li><li>Экспортировать собственные отчёты и хранить рабочие заметки без секретных данных.</li></ul>
      <h2>Запрещено</h2><ul><li>Использовать сервис для доксинга, преследования, угроз, шантажа или деанонимизации частных лиц.</li><li>Проверять чужие системы без разрешения, обходить авторизацию, запускать эксплойты или нарушать доступность ресурсов.</li><li>Собирать, хранить или раскрывать пароли, токены, полные номера карт, CVV, приватные ключи и иные секреты.</li><li>Массово автоматизировать запросы к источникам с нарушением их правил или обходить лимиты.</li><li>Представлять неполные публичные данные как подтверждение взлома, преступления или личности.</li></ul>
      <h2>Ответственное исследование</h2><p>Соблюдай минимально необходимый объём запроса, частотные ограничения, условия API, законы и требования владельца системы. При обнаружении уязвимости не используй её для доступа к данным; сообщи владельцу через официальный канал раскрытия.</p>
      <h2>Реакция на нарушение</h2><p>Оператор может ограничить доступ к функции или аккаунту при обоснованном подозрении на злоупотребление, сохраняя права пользователя и обязательные требования закона. Обращения: <b>killedofficialbd@gmail.com</b>.</p>`
  }
};

let currentUser = null;
let gateMode = false;
let activeDoc = 'terms';
let readError = '';
let serverVerified = false;

function ensureLayer(){
  if($('#pgLegalLayer')) return;
  document.body.insertAdjacentHTML('beforeend', `<div class="pg-legal-layer" id="pgLegalLayer" hidden><section class="pg-legal-modal" role="dialog" aria-modal="true" aria-labelledby="pgLegalTitle"><header class="pg-legal-top"><div class="pg-legal-brand"><span class="pg-legal-logo">PG</span><span><b>PrivacyGuard</b><small>TRUST & TRANSPARENCY CENTER</small></span></div><span class="pg-legal-version">DOCUMENTS · 3.1</span></header><div class="pg-legal-heading"><span class="pg-pill">ОБЯЗАТЕЛЬНЫЕ ДОКУМЕНТЫ</span><h1 id="pgLegalTitle">Перед тем как продолжить</h1><p id="pgLegalIntro">Прочитай документы и подтверди каждый пункт отдельно. Подтверждение будет сохранено в твоём Firebase-аккаунте.</p></div><nav class="pg-legal-tabs" aria-label="Документы">${Object.entries(docs).map(([id,d])=>`<button type="button" data-pg-legal-tab="${id}">${d.label}</button>`).join('')}</nav><article class="pg-legal-document" id="pgLegalDocument" tabindex="0"></article><div class="pg-legal-checks" id="pgLegalChecks"><label><input type="checkbox" id="pgAcceptTerms"><span>Я прочитал(а) и принимаю <b>Пользовательское соглашение</b>.</span></label><label><input type="checkbox" id="pgAckPrivacy"><span>Я ознакомился(лась) с <b>Политикой конфиденциальности</b> и понимаю, какие данные обрабатываются.</span></label><label><input type="checkbox" id="pgAcceptAup"><span>Я прочитал(а) и принимаю <b>Правила допустимого использования</b>.</span></label></div><div class="pg-legal-status" id="pgLegalStatus" aria-live="polite"></div><footer class="pg-legal-actions"><button type="button" class="btn btn-ghost" id="pgLegalDecline">Не принимаю · Выйти</button><button type="button" class="btn btn-ghost" id="pgLegalClose" hidden>Закрыть</button><button type="button" class="btn btn-primary" id="pgLegalRetry" hidden>Проверить снова</button><button type="button" class="btn btn-primary" id="pgLegalConfirm" disabled>Подтвердить и продолжить</button></footer><small class="pg-legal-footnote">Необязательное маркетинговое согласие не запрашивается. Ознакомление с политикой и принятие условий фиксируются раздельными отметками.</small></section></div>`);
  $('#pgLegalDecline').addEventListener('click', async()=>{if(!currentUser)return;await signOut(auth).catch(()=>{});});
  $('#pgLegalConfirm').addEventListener('click', acceptCurrent);
  $('#pgLegalRetry').addEventListener('click', verifyAcceptance);
  $('#pgLegalClose').addEventListener('click',()=>{if(!gateMode)$('#pgLegalLayer').hidden=true;});
  $('#pgLegalChecks').addEventListener('change',updateConfirmState);
  $('#pgLegalLayer').addEventListener('click',e=>{const tab=e.target.closest('[data-pg-legal-tab]');if(tab){activeDoc=tab.dataset.pgLegalTab;renderDoc();}});
}
function renderDoc(){
  const d=docs[activeDoc];
  $('#pgLegalDocument').innerHTML=`<div class="pg-legal-doc-meta"><span>${d.label}</span><b>Версия ${d.version} · 04.11.2026</b></div>${d.body}`;
  document.querySelectorAll('[data-pg-legal-tab]').forEach(b=>b.classList.toggle('active',b.dataset.pgLegalTab===activeDoc));
}
function updateConfirmState(){
  const complete=$('#pgAcceptTerms')?.checked&&$('#pgAckPrivacy')?.checked&&$('#pgAcceptAup')?.checked;
  $('#pgLegalConfirm').disabled=!complete||!serverVerified||!navigator.onLine;
}
function showLayer({gate=false,error=''}={}){
  ensureLayer();gateMode=gate;readError=error;$('#pgLegalLayer').hidden=false;
  $('#pgLegalTitle').textContent=gate?'Перед тем как продолжить':'Документы PrivacyGuard';
  $('#pgLegalIntro').textContent=gate?'Для доступа к аккаунту подтверди три пункта. Версии и время будут записаны в Firestore под твоим Firebase UID.':'Актуальные документы сервиса. Операторские реквизиты и отдельные сроки хранения необходимо заполнить перед публичным запуском.';
  $('#pgLegalChecks').hidden=!gate;$('#pgLegalDecline').hidden=!gate;$('#pgLegalClose').hidden=gate;$('#pgLegalConfirm').hidden=!gate;$('#pgLegalRetry').hidden=!gate;
  if(gate){$('#pgAcceptTerms').checked=false;$('#pgAckPrivacy').checked=false;$('#pgAcceptAup').checked=false;}
  $('#pgLegalStatus').textContent=error|| (gate?'Проверяем, можно ли подтвердить документы…':'Документы доступны для просмотра.');
  renderDoc();updateConfirmState();
  if(gate)$('#pgLegalDocument').scrollTop=0;
}
function acceptanceRef(){return doc(db,'users',currentUser.uid,'legalAcceptances',ACCEPTANCE_ID);}
function isCurrentRecord(data){return !!data&&data.termsVersion===TERMS_VERSION&&data.privacyVersion===PRIVACY_VERSION&&data.acceptableUseVersion===AUP_VERSION&&data.acceptedTerms===true&&data.acknowledgedPrivacy===true&&data.acceptedAcceptableUse===true;}
async function verifyAcceptance(){
  if(!currentUser)return;
  ensureLayer();serverVerified=false;$('#pgLegalRetry').hidden=true;$('#pgLegalStatus').textContent='Проверяем подтверждение на сервере Firebase…';updateConfirmState();
  const ref=acceptanceRef();
  try{
    const snap=await getDocFromServer(ref);
    if(snap.exists()&&isCurrentRecord(snap.data())){serverVerified=true;$('#pgLegalLayer').hidden=true;updateRecordStatus(snap.data());return;}
    serverVerified=true;showLayer({gate:true,error:'Нужно подтвердить текущие версии документов. Отметки не выбраны заранее.'});
    $('#pgLegalStatus').textContent='Подтверждения текущих версий ещё нет. Отметь три пункта и нажми «Подтвердить и продолжить».';
    updateConfirmState();
  }catch(error){
    try{
      const cached=await getDocFromCache(ref);
      if(cached.exists()&&isCurrentRecord(cached.data())){serverVerified=true;$('#pgLegalLayer').hidden=true;updateRecordStatus(cached.data());return;}
    }catch{}
    serverVerified=false;showLayer({gate:true,error:'Не удалось проверить подтверждение в Firebase. Подключись к интернету и повтори попытку.'});
    $('#pgLegalStatus').textContent=`${window.PGErrorCode?.(error)||'PG-FS-503'} · ${navigator.onLine?'Firestore недоступен или правила не опубликованы.':'Нет подключения к интернету.'}`;
    $('#pgLegalRetry').hidden=false;updateConfirmState();
  }
}
async function acceptCurrent(){
  if(!currentUser||!serverVerified||!navigator.onLine)return;
  if(!$('#pgAcceptTerms').checked||!$('#pgAckPrivacy').checked||!$('#pgAcceptAup').checked)return;
  const button=$('#pgLegalConfirm');button.disabled=true;button.textContent='Сохраняем в Firebase…';
  const record={termsVersion:TERMS_VERSION,privacyVersion:PRIVACY_VERSION,acceptableUseVersion:AUP_VERSION,acceptedTerms:true,acknowledgedPrivacy:true,acceptedAcceptableUse:true,method:'explicit-checkboxes',locale:'ru',appVersion:APP_VERSION,acceptedAt:serverTimestamp()};
  try{
    const ref=acceptanceRef();
    try{await setDoc(ref,record);}catch(writeError){const existing=await getDocFromServer(ref).catch(()=>null);if(!existing?.exists()||!isCurrentRecord(existing.data()))throw writeError;}
    const confirmed=await getDocFromServer(ref);
    if(!confirmed.exists()||!isCurrentRecord(confirmed.data()))throw new Error('Firebase не подтвердил сохранение текущей версии документов.');
    $('#pgLegalLayer').hidden=true;updateRecordStatus(confirmed.data());
    window.dispatchEvent(new CustomEvent('pg:legal-accepted',{detail:{uid:currentUser.uid,recordId:ACCEPTANCE_ID}}));
    document.dispatchEvent(new CustomEvent('pg:toast',{detail:{message:'Подтверждение сохранено в Firebase.'}}));
  }catch(error){
    $('#pgLegalStatus').textContent=`${window.PGErrorCode?.(error)||'PG-FS-503'} · Не удалось надёжно подтвердить запись в Firebase: ${error.message||'ошибка записи'}`;
    $('#pgLegalRetry').hidden=false;
  }finally{button.textContent='Подтвердить и продолжить';updateConfirmState();}
}
function updateRecordStatus(data){
  const host=$('#pgLegalRecordStatus');if(!host)return;
  const date=data?.acceptedAt?.toDate?data.acceptedAt.toDate().toLocaleString('ru-RU'):'дата хранится в Firestore';
  host.textContent=`Подтверждено: ${date} · Terms ${data.termsVersion}, Privacy ${data.privacyVersion}, Acceptable Use ${data.acceptableUseVersion}.`;
}
function openDocument(id){if(!docs[id])return;activeDoc=id;showLayer({gate:false});}

document.addEventListener('click',e=>{
  const open=e.target.closest('[data-legal-open]');if(open){e.preventDefault();openDocument(open.dataset.legalOpen);return;}
  if(e.target.closest('[data-legal-review]')){if(!currentUser)return;verifyAcceptance();}
});
onAuthStateChanged(auth,async user=>{
  currentUser=user||null;
  if(!user){if($('#pgLegalLayer'))$('#pgLegalLayer').hidden=true;return;}
  await verifyAcceptance();
});
