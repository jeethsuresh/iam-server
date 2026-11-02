// Upgrade a real, persistent Synapse 1.56 database to the pinned modern release.
// There is no capability override: the worker polls the peer's actual API.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {api,start,deliver,operations,until,event,clients,passed,pass} from './legacy.mjs';
const native='https://native.test:8448', reference='https://reference.test:8448';
const escape=encodeURIComponent, rooms=[];
try {
  const a=await api({base:native},'/_matrix/client/v3/login',{type:'m.login.password',identifier:{type:'m.id.user',user:'cryptoalice'},password:'password123',device_id:'VERSION_A'});
  const b=await api({base:reference},'/_matrix/client/v3/register',{username:'versionpeer',password:'isolated-test-password',auth:{type:'m.login.dummy'},device_id:'VERSION_B'});
  const actors=[{...a,base:native},{...b,base:reference}];
  const [host,peer]=actors;await Promise.all(actors.map(start));
  for(const encrypted of [false,true]){
    const created=await host.client.createRoom({name:'Automatic version upgrade',preset:'private_chat',invite:[peer.user_id],...(encrypted?{initial_state:[{type:'m.room.encryption',state_key:'',content:{algorithm:'m.megolm.v1.aes-sha2'}}]}:{})});
    const old=created.room_id;
    await until('automatic version-nine invite',()=>peer.client.getRoom(old)?.getMyMembership()==='invite');
    await peer.client.joinRoom(old);
    await until('old conversation joined',()=>host.client.getRoom(old)?.getMember(peer.user_id)?.membership==='join');
    const create=await api(host,'/_matrix/client/v3/rooms/'+escape(old)+'/state/m.room.create');
    assert.equal(create.room_version,'9');pass('new conversation automatically uses real old-peer capabilities');
    if(encrypted)for(const [source,target] of [[host,peer],[peer,host]]){
      await until('version test device keys available',async()=> (await source.client.getCrypto().getUserDeviceInfo([target.user_id],true)).get(target.user_id)?.has(target.device_id));
      await source.client.getCrypto().setDeviceVerified(target.user_id,target.device_id);
    }
    await operations(host,peer,old,encrypted);await operations(peer,host,old,encrypted);
    const content={msgtype:'m.text',body:'History before the peer update'};
    const retained=await deliver(host,peer,old,'m.room.message',content,'retained pre-upgrade history');
    rooms.push({old,encrypted,retained,content});
  }
  await api(host,'/_matrix/client/v3/user/'+escape(host.user_id)+'/account_data/m.direct',{[peer.user_id]:rooms.filter(r=>r.encrypted).map(r=>r.old)},'PUT');
  writeFileSync('/results/upgrade-peer','ready');
  for(const r of rooms){
    let replacement;
    await until('background worker upgrades after the actual server update',async()=>{
      const room=host.client.getRoom(r.old);
      const tombstone=room?.currentState.getStateEvents('m.room.tombstone','')?.getContent();
      replacement=tombstone?.replacement_room;return Boolean(replacement);
    },180000);
    const create=await api(host,'/_matrix/client/v3/rooms/'+escape(replacement)+'/state/m.room.create');
    assert.equal(create.room_version,'12');assert.equal(create.predecessor.room_id,r.old);
    await until('replacement invitation delivered',()=>peer.client.getRoom(replacement)?.getMyMembership()==='invite');
    await peer.client.joinRoom(replacement);
    await until('replacement joined on both servers',()=>host.client.getRoom(replacement)?.getMember(peer.user_id)?.membership==='join');
    assert.deepEqual((await event(peer,r.old,r.retained))?.getContent(),r.content);pass('old decrypted history retained after automatic replacement');
    const encryption=host.client.getRoom(replacement).hasEncryptionStateEvent();assert.equal(Boolean(encryption),r.encrypted);
    peer.modernMedia=(await api(peer,'/_matrix/client/versions')).versions.some(v=>/^v1\.(?:1[1-9]|[2-9][0-9])$/.test(v));
    await operations(host,peer,replacement,r.encrypted);await operations(peer,host,replacement,r.encrypted);
    const state=await api(host,'/_matrix/client/v3/rooms/'+escape(r.old)+'/state/m.room.tombstone');assert.equal(state.replacement_room,replacement);
    if(r.encrypted){const direct=await api(host,'/_matrix/client/v3/user/'+escape(host.user_id)+'/account_data/m.direct');assert.deepEqual(direct[peer.user_id],[replacement]);pass('direct conversation follows the current replacement');}
  }
  // Rechecks must not create a chain of replacements while support is unchanged.
  await new Promise(r=>setTimeout(r,12000));
  for(const r of rooms){const target=host.client.getRoom(r.old).currentState.getStateEvents('m.room.tombstone','').getContent().replacement_room;assert.ok(!host.client.getRoom(target).currentState.getStateEvents('m.room.tombstone',''));}
  pass('periodic reconciliation is idempotent');
  console.log('ROOM VERSIONS COMPLETE '+passed.length+' checks against a real peer update');
} finally {for(const client of clients)client.stopClient();}
process.exit(0);
