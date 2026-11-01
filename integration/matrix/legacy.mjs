// Real two-server regression for the oldest supported peer (Synapse 1.56 / v9).
// The optional session file uses only explicitly provisioned disposable actors.
import assert from 'node:assert/strict';
import {readFileSync, writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {createClient, ClientEvent} from 'matrix-js-sdk';
import {Attachment, EncryptedAttachment} from '@matrix-org/matrix-sdk-crypto-wasm';
import {logger} from 'matrix-js-sdk/lib/logger.js';
logger.setLevel('error');
const clients = [], rooms = [], passed = [];
const escape = encodeURIComponent;
const suffix = Date.now().toString();
const fixtureNative = 'https://native.test:8448', fixtureReference = 'https://reference.test:8448';
async function api(actor, path, data, method) {
  const response = await fetch(actor.base + path, {method: method || (data ? 'POST' : 'GET'), headers: {'Content-Type':'application/json', ...(actor.access_token ? {Authorization:'Bearer '+actor.access_token} : {})}, ...(data ? {body:JSON.stringify(data)} : {})});
  const body = await response.json();
  if (!response.ok) throw Object.assign(new Error(`${response.status} ${body.errcode}: ${body.error}`), {status:response.status});
  return body;
}
function pass(label) {passed.push(label);console.log('LEGACY PASS '+label);}
async function until(label, check) {
  const end = Date.now() + 45000;
  while (Date.now() < end) {if (await check()) {pass(label);return;} await new Promise(resolve=>setTimeout(resolve,250));}
  throw new Error('Timed out: '+label);
}
async function start(actor) {
  const client = createClient({baseUrl:actor.base,userId:actor.user_id,deviceId:actor.device_id,accessToken:actor.access_token});
  clients.push(client);actor.client=client;
  await client.initRustCrypto({useIndexedDB:false});
  const ready = new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('Initial sync timed out')),45000);
    client.on(ClientEvent.Sync,state=>{if(state==='PREPARED'){clearTimeout(timer);resolve();}});
  });
  await client.startClient({initialSyncLimit:100,pollTimeout:1000});await ready;
  const versions=await api(actor,'/_matrix/client/versions');
  actor.modernMedia=versions.versions.some(v=>/^v1\.(?:1[1-9]|[2-9][0-9])$/.test(v));
}
async function event(actor,room,id) {
  const event=actor.client.getRoom(room)?.getLiveTimeline().getEvents().find(e=>e.getId()===id);
  if(event) await actor.client.decryptEventIfNeeded(event);
  return event;
}
async function deliver(source,target,room,type,content,label) {
  const sent=await source.client.sendEvent(room,type,content);
  await until(label,async()=>isDeepStrictEqual((await event(target,room,sent.event_id))?.getContent(),content));
  return sent.event_id;
}
async function download(actor,url,thumbnail=false) {
  const [server,id]=url.slice(6).split('/');
  const prefix=actor.modernMedia?'/_matrix/client/v1/media/':'/_matrix/media/v3/';
  const response=await fetch(actor.base+prefix+(thumbnail?'thumbnail/':'download/')+escape(server)+'/'+escape(id)+(thumbnail?'?width=32&height=32&method=scale':''),{headers:{Authorization:'Bearer '+actor.access_token}});
  assert.equal(response.status,200,`Media download from ${actor.base}: ${response.status} ${response.ok?'':await response.text()}`);
  return new Uint8Array(await response.arrayBuffer());
}
async function file(source,target,room,encrypted,image=false) {
  const plain=image?new Uint8Array(Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACAQMAAABIeJ9nAAAAA1BMVEUAAIBKwr76AAAADElEQVQI12NgYGAAAAAEAAEnNCcKAAAAAElFTkSuQmCC','base64')):new Uint8Array(Array.from({length:4096},(_,i)=>(i*31)%256));
  const crypto=encrypted?Attachment.encrypt(plain):null;
  const bytes=crypto?crypto.encryptedData:plain;
  const response=await fetch(source.base+'/_matrix/media/v3/upload?filename='+ (image?'preview.png':'verification.bin'),{method:'POST',headers:{Authorization:'Bearer '+source.access_token,'Content-Type':encrypted?'application/octet-stream':image?'image/png':'application/octet-stream'},body:bytes});
  assert.equal(response.status,200);
  const uploaded=await response.json(),url=uploaded.content_uri;
  const content={msgtype:image?'m.image':'m.file',body:image?'preview.png':'verification.bin',info:{mimetype:image?'image/png':'application/octet-stream',size:plain.length}};
  if(crypto)content.file={...JSON.parse(crypto.mediaEncryptionInfo),url};else content.url=url;
  await deliver(source,target,room,'m.room.message',content,`${source.user_id} -> ${target.user_id} ${encrypted?'encrypted ':''}${image?'image':'file'} metadata`);
  const received=await download(target,url);
  const expected=await download(source,url);
  assert.deepEqual(received,expected);
  if(crypto){assert.deepEqual(Attachment.decrypt(new EncryptedAttachment(received,JSON.stringify(content.file))),plain);crypto.free();}
  else if(!image)assert.deepEqual(received,plain);
  pass(`verified attachment bytes ${createHash('sha256').update(received).digest('hex')} from ${source.user_id}`);
  if(image&&!encrypted){assert.ok((await download(target,url,true)).length>0);pass('federated image thumbnail');}
}
async function ephemeral(actor,room,type,predicate) {
  const sync=await api(actor,'/_matrix/client/v3/sync?timeout=0'+(actor.since?'&since='+escape(actor.since):''));
  actor.since=sync.next_batch;
  return (sync.rooms?.join?.[room]?.ephemeral?.events||[]).some(e=>e.type===type&&predicate(e.content));
}
async function operations(source,target,room,encrypted) {
  const prefix=source.user_id+' -> '+target.user_id+(encrypted?' encrypted':' plaintext');
  const original=await deliver(source,target,room,'m.room.message',{msgtype:'m.text',body:'Federation verification '+suffix},prefix+' message');
  await deliver(source,target,room,'m.room.message',{msgtype:'m.text',body:'Reply '+suffix,'m.relates_to':{'m.in_reply_to':{event_id:original}}},prefix+' reply');
  await deliver(source,target,room,'m.room.message',{msgtype:'m.text',body:'Thread '+suffix,'m.relates_to':{rel_type:'m.thread',event_id:original,is_falling_back:true,'m.in_reply_to':{event_id:original}}},prefix+' thread');
  const reaction=await deliver(source,target,room,'m.reaction',{'m.relates_to':{rel_type:'m.annotation',event_id:original,key:'👍'}},prefix+' reaction');
  await deliver(source,target,room,'m.room.message',{msgtype:'m.text',body:'* Edited '+suffix,'m.new_content':{msgtype:'m.text',body:'Edited '+suffix},'m.relates_to':{rel_type:'m.replace',event_id:original}},prefix+' edit');
  await source.client.redactEvent(room,reaction);
  await until(prefix+' reaction removal',async()=> (await event(target,room,reaction))?.isRedacted());
  await file(source,target,room,encrypted);
  await file(source,target,room,encrypted,true);
  await ephemeral(target,room,'m.typing',()=>false);
  await api(source,'/_matrix/client/v3/rooms/'+escape(room)+'/typing/'+escape(source.user_id),{typing:true,timeout:10000},'PUT');
  await until(prefix+' typing',()=>ephemeral(target,room,'m.typing',c=>c.user_ids.includes(source.user_id)));
  await api(source,'/_matrix/client/v3/rooms/'+escape(room)+'/typing/'+escape(source.user_id),{typing:false},'PUT');
  await api(source,'/_matrix/client/v3/rooms/'+escape(room)+'/receipt/m.read/'+escape(original),{});
  await until(prefix+' read receipt',()=>ephemeral(target,room,'m.receipt',c=>Boolean(c[original]?.['m.read']?.[source.user_id])));
  const history=await api(target,'/_matrix/client/v3/rooms/'+escape(room)+'/messages?dir=b&limit=100');
  assert.ok(history.chunk.some(e=>e.event_id===original));pass(prefix+' paginated history');
  await source.client.redactEvent(room,original);
  await until(prefix+' message deletion',async()=> (await event(target,room,original))?.isRedacted());
}
let actors;
try {
  if(process.env.MATRIX_LIVE_SESSIONS){
    actors=JSON.parse(readFileSync(process.env.MATRIX_LIVE_SESSIONS,'utf8'));
    assert.deepEqual(actors.map(a=>a.base),['https://chat.gravitas.cool','https://matrix.jeethsuresh.com']);
    assert.ok(actors.every(a=>/^@rqf[a-f0-9]{8}:/.test(a.user_id)),'Only disposable actors are allowed');
  }else{
    const a=await api({base:fixtureNative},'/_matrix/client/v3/login',{type:'m.login.password',identifier:{type:'m.id.user',user:'cryptoalice'},password:'password123',device_id:'LEGACY_A_'+suffix});
    const b=await api({base:fixtureReference},'/_matrix/client/v3/register',{username:'legacy'+suffix,password:'test-password-123',auth:{type:'m.login.dummy'},device_id:'LEGACY_B_'+suffix});
    actors=[{...a,base:fixtureNative},{...b,base:fixtureReference}];
  }
  await Promise.all(actors.map(start));pass('both real Rust-crypto clients synchronized');
  for(const encrypted of [false,true])for(const host of actors){
    const peer=actors.find(a=>a!==host);
    const created=await host.client.createRoom({name:'Disposable federation verification '+suffix,room_version:'9',preset:'private_chat',invite:[peer.user_id],...(encrypted?{initial_state:[{type:'m.room.encryption',state_key:'',content:{algorithm:'m.megolm.v1.aes-sha2'}}]}:{})});
    const room=created.room_id;rooms.push({room,host:host.base,encrypted});
    await until('invitation delivered from '+host.user_id,()=>peer.client.getRoom(room)?.getMyMembership()==='invite');
    await peer.client.joinRoom(room);
    await until('signed join on both servers',()=>host.client.getRoom(room)?.getMember(peer.user_id)?.membership==='join'&&peer.client.getRoom(room)?.getMyMembership()==='join');
  // Trust only the two freshly provisioned test devices after retrieving their keys.
  for(const [source,target] of [[actors[0],actors[1]],[actors[1],actors[0]]]){
    if(encrypted){
      await until('public device keys available for '+target.user_id,async()=>{
        const devices=await source.client.getCrypto().getUserDeviceInfo([target.user_id],true);
        return devices.get(target.user_id)?.has(target.device_id);
      });
      await source.client.getCrypto().setDeviceVerified(target.user_id,target.device_id);
    }
  }

    for(const [source,target] of [[host,peer],[peer,host]])await operations(source,target,room,encrypted);
    await peer.client.leave(room);
    await until('federated leave',()=>host.client.getRoom(room)?.getMember(peer.user_id)?.membership==='leave');
    await assert.rejects(api(peer,'/_matrix/client/v3/rooms/'+escape(room)+'/send/m.room.message/'+suffix,{msgtype:'m.text',body:'must be rejected'},'PUT'),e=>e.status===403);
    pass('departed member cannot send');
    await host.client.leave(room);
  }
  console.log('LEGACY COMPLETE '+passed.length+' checks');
}finally{
  for(const client of clients)client.stopClient();
  if(process.env.MATRIX_LIVE_REPORT)writeFileSync(process.env.MATRIX_LIVE_REPORT,JSON.stringify({passed,rooms},null,2));
}
process.exit(0);
