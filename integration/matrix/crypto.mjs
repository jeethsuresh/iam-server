import assert from 'node:assert/strict';
import { createClient, ClientEvent, RoomEvent } from 'matrix-js-sdk';
import { Attachment, EncryptedAttachment } from '@matrix-org/matrix-sdk-crypto-wasm';
import { logger } from 'matrix-js-sdk/lib/logger.js';
logger.setLevel('warn');
const clients = [];
const native = 'https://native.test:8448';
const reference = 'https://reference.test:8448';
const suffix = Date.now().toString();
async function json(base, path, body, token, method) {
  const response = await fetch(base + path, {method: method || (body ? 'POST' : 'GET'),
    headers: {'Content-Type': 'application/json', ...(token ? {Authorization: 'Bearer ' + token} : {})},
    ...(body ? {body: JSON.stringify(body)} : {})});
  const data = await response.json();
  if (!response.ok) throw Object.assign(new Error(data.errcode + ': ' + data.error), {status: response.status, data});
  return data;
}
async function until(label, check, timeout = 45000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await check()) {console.log('CRYPTO PASS ' + label); return;} await new Promise(r => setTimeout(r, 200)); }
  throw new Error('Timed out: ' + label);
}
async function start(base, session, secretKeys = new Map()) {
  const client = createClient({baseUrl: base, userId: session.user_id, deviceId: session.device_id, accessToken: session.access_token,
    cryptoCallbacks: {
      cacheSecretStorageKey: (id, _info, key) => secretKeys.set(id, key),
      getSecretStorageKey: async ({keys}) => {
        for (const id of Object.keys(keys)) if (secretKeys.has(id)) return [id, secretKeys.get(id)];
        return null;
      }
    }});
  client.interopSecretKeys = secretKeys;
  clients.push(client);
  await client.initRustCrypto({useIndexedDB: false});
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Initial sync timeout')), 45000);
    client.on(ClientEvent.Sync, state => { if (state === 'PREPARED') {clearTimeout(timer); resolve();} });
  });
  await client.startClient({initialSyncLimit: 100, pollTimeout: 1000});
  await ready;
  return client;
}
try {
  const a = await json(native, '/_matrix/client/v3/login', {type: 'm.login.password', identifier: {type: 'm.id.user', user: 'cryptoalice'}, password: 'password123', device_id: 'CRYPTO_A_' + suffix, refresh_token: true});
  const refreshed = await json(native, '/_matrix/client/v3/refresh', {refresh_token: a.refresh_token});
  assert.ok(refreshed.expires_in_ms > 0);
  a.access_token = refreshed.access_token;
  const rules = await json(native, '/_matrix/client/v3/pushrules/', null, a.access_token);
  assert.ok(rules.global.override.some(rule => rule.rule_id === '.m.rule.is_user_mention'));
  console.log('CRYPTO PASS refresh credentials and Matrix 1.19 default push rules');
  const b = await json(reference, '/_matrix/client/v3/register', {username: 'crypto' + suffix, password: 'test-password-123', auth: {type: 'm.login.dummy'}, device_id: 'CRYPTO_B_' + suffix});
  const alice = await start(native, a);
  const bob = await start(reference, b);
  console.log('CRYPTO PASS both Rust-backed SDK clients initialized');
  const jsonBytes = new TextEncoder().encode('{ "base64": "SGVsbG8=", "_json": [1, 2] }\n');
  const jsonUpload = await fetch(native + '/_matrix/media/v3/upload?filename=metadata.json', {
    method: 'POST', headers: {Authorization: 'Bearer ' + a.access_token, 'Content-Type': 'application/json'}, body: jsonBytes
  });
  assert.equal(jsonUpload.status, 200);
  const jsonUri = (await jsonUpload.json()).content_uri;
  const [jsonServer, jsonId] = jsonUri.slice('mxc://'.length).split('/');
  const jsonDownload = await fetch(reference + '/_matrix/client/v1/media/download/' + encodeURIComponent(jsonServer) + '/' + encodeURIComponent(jsonId), {
    headers: {Authorization: 'Bearer ' + b.access_token}
  });
  assert.equal(jsonDownload.status, 200);
  assert.ok(jsonDownload.headers.get('content-type').startsWith('application/json'));
  assert.deepEqual(new Uint8Array(await jsonDownload.arrayBuffer()), jsonBytes);
  console.log('CRYPTO PASS JSON media bytes and MIME type survive upload and federated download');

  for (const client of [alice, bob]) {
    await client.getCrypto().userHasCrossSigningKeys(client.getUserId(), true);
    await client.getCrypto().bootstrapSecretStorage({setupNewSecretStorage: true,
      createSecretStorageKey: () => client.getCrypto().createRecoveryKeyFromPassphrase()});
    await client.getCrypto().bootstrapCrossSigning({setupNewCrossSigning: true, authUploadDeviceSigningKeys: async request => {
      try { return await request({}); } catch (error) {
        if (error.httpStatus !== 401 || !error.data?.session) throw error;
        return request({type: 'm.login.password', session: error.data.session,
          identifier: {type: 'm.id.user', user: client.getUserId()}, password: client === alice ? 'password123' : 'test-password-123'});
      }
    }});
  }
  console.log('CRYPTO PASS both clients published cross-signing identities');
  const {room_id: room} = await alice.createRoom({name: 'Encrypted interoperability', preset: 'private_chat', room_version: '12',
    invite: [b.user_id], initial_state: [{type: 'm.room.encryption', state_key: '', content: {algorithm: 'm.megolm.v1.aes-sha2'}}]});
  await until('signed invite reaches Synapse client', () => bob.getRoom(room)?.getMyMembership() === 'invite');
  await bob.joinRoom(room);
  await until('both clients observe the joined encrypted room', () => alice.getRoom(room)?.getMember(b.user_id)?.membership === 'join' && bob.getRoom(room)?.getMyMembership() === 'join');
  await alice.getCrypto().getUserDeviceInfo([b.user_id], true);
  await bob.getCrypto().getUserDeviceInfo([a.user_id], true);
  await alice.getCrypto().setDeviceVerified(b.user_id, b.device_id);
  await bob.getCrypto().setDeviceVerified(a.user_id, a.device_id);
  console.log('CRYPTO PASS peers retrieved and trusted each other\'s public device keys');
  const plainA = 'secret from Gravitas ' + suffix;
  const plainB = 'secret from Synapse ' + suffix;
  const sentA = await alice.sendTextMessage(room, plainA);
  await until('Synapse client decrypts Gravitas Megolm message', async () => {
    const events = bob.getRoom(room)?.getLiveTimeline().getEvents() || [];
    const event = events.find(e => e.getId() === sentA.event_id);
    if (event) await bob.decryptEventIfNeeded(event);
    return event?.getContent().body === plainA;
  });
  const sentB = await bob.sendTextMessage(room, plainB);
  await until('Gravitas client decrypts Synapse Megolm message', async () => {
    const event = alice.getRoom(room)?.getLiveTimeline().getEvents().find(e => e.getId() === sentB.event_id);
    if (event) await alice.decryptEventIfNeeded(event);
    return event?.getContent().body === plainB;
  });
  for (const sent of [sentA, sentB]) {
    const wire = await json(native, '/_matrix/client/v3/rooms/' + encodeURIComponent(room) + '/event/' + encodeURIComponent(sent.event_id), null, a.access_token);
    assert.equal(wire.type, 'm.room.encrypted');
    assert.equal(typeof wire.content.ciphertext, 'string');
    assert(!JSON.stringify(wire).includes(plainA));
    assert(!JSON.stringify(wire).includes(plainB));
  }
  console.log('CRYPTO PASS homeserver event API exposes ciphertext only');
  const noticePage = await json(native, '/_matrix/client/v3/notifications', null, a.access_token);
  const encryptedNotice = noticePage.notifications.find(item => item.event.event_id === sentB.event_id);
  assert.ok(encryptedNotice && encryptedNotice.event.type === 'm.room.encrypted');
  assert.equal(encryptedNotice.event.content.body, undefined);
  await json(native, `/_matrix/client/v3/rooms/${encodeURIComponent(room)}/receipt/m.read.private/${encodeURIComponent(sentB.event_id)}`, {}, a.access_token);
  const readNotices = await json(native, '/_matrix/client/v3/notifications', null, a.access_token);
  assert.equal(readNotices.notifications.find(item => item.event.event_id === sentB.event_id).read, true);
  console.log('CRYPTO PASS federated encrypted notifications and private read receipts');

  for (const [sender, receiver, source, target, session] of [[alice, bob, native, reference, b], [bob, alice, reference, native, a]]) {
    const plain = new TextEncoder().encode('private attachment from ' + source + ' ' + suffix);
    const encrypted = Attachment.encrypt(plain);
    const info = JSON.parse(encrypted.mediaEncryptionInfo);
    const cipher = encrypted.encryptedData;
    const uploaded = await fetch(source + '/_matrix/media/v3/upload?filename=encrypted.bin', {method: 'POST',
      headers: {Authorization: 'Bearer ' + sender.getAccessToken(), 'Content-Type': 'application/octet-stream'}, body: cipher});
    assert(uploaded.ok, 'encrypted attachment upload failed: ' + uploaded.status);
    const {content_uri: url} = await uploaded.json();
    const sent = await sender.sendMessage(room, {msgtype: 'm.file', body: 'private.bin', file: {...info, url}});
    let content;
    await until('peer receives encrypted attachment metadata from ' + source, async () => {
      const event = receiver.getRoom(room)?.getLiveTimeline().getEvents().find(e => e.getId() === sent.event_id);
      if (event) await receiver.decryptEventIfNeeded(event);
      content = event?.getContent();
      return content?.file?.url === url;
    });
    const [server, id] = url.slice('mxc://'.length).split('/');
    const downloaded = await fetch(target + '/_matrix/client/v1/media/download/' + encodeURIComponent(server) + '/' + encodeURIComponent(id),
      {headers: {Authorization: 'Bearer ' + session.access_token}});
    assert(downloaded.ok, 'federated attachment download failed: ' + downloaded.status + ' ' + await (downloaded.ok ? Promise.resolve('') : downloaded.text()));
    const received = new Uint8Array(await downloaded.arrayBuffer());
    assert.deepEqual(received, cipher);
    const restored = Attachment.decrypt(new EncryptedAttachment(received, JSON.stringify(content.file)));
    assert.deepEqual(restored, plain);
    encrypted.free();
    console.log('CRYPTO PASS encrypted attachment transfers and decrypts from ' + source);
  }
  await alice.getCrypto().resetKeyBackup();
  await until('client-encrypted session backup reaches Gravitas', async () => {
    const version = await json(native, '/_matrix/client/v3/room_keys/version', null, a.access_token);
    return version.count > 0;
  });
  const c = await json(native, '/_matrix/client/v3/login', {type: 'm.login.password', identifier: {type: 'm.id.user', user: 'cryptoalice'}, password: 'password123', device_id: 'CRYPTO_C_' + suffix});
  const recovered = await start(native, c, alice.interopSecretKeys);
  assert(await recovered.getCrypto().userHasCrossSigningKeys(a.user_id, true));
  await recovered.getCrypto().bootstrapCrossSigning({authUploadDeviceSigningKeys: request => request({})});
  assert(await recovered.getCrypto().isCrossSigningReady());
  await recovered.getCrypto().loadSessionBackupPrivateKeyFromSecretStorage();
  await recovered.getCrypto().restoreKeyBackup();
  await until('fresh device restores and decrypts prior ciphertext using the encrypted backup', async () => {
    const event = recovered.getRoom(room)?.getLiveTimeline().getEvents().find(e => e.getId() === sentB.event_id);
    if (event) await recovered.decryptEventIfNeeded(event);
    return event?.getContent().body === plainB;
  });
  const masterSecret = await json(native, '/_matrix/client/v3/user/' + encodeURIComponent(a.user_id) + '/account_data/m.cross_signing.master', null, a.access_token);
  assert(masterSecret.encrypted && Object.keys(masterSecret.encrypted).length > 0);
  for (const key of alice.interopSecretKeys.values()) assert(!JSON.stringify(masterSecret).includes(Buffer.from(key).toString('base64')));
  console.log('CRYPTO PASS secret-storage API contains only encrypted secrets');
  console.log('CRYPTO COMPLETE');
} finally {
  for (const client of clients) client.stopClient();
}

process.exit(0);
