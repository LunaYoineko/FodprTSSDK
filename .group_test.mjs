import { WebSocket } from 'ws';
import {
  Protocol,
  CryptoUtils,
  TransTypeGroup,
  MsgTypeEvent,
  MsgTypePush,
} from '/root/FodprTSSDK/dist/index.js';

const RELAY = 'ws://localhost:8100/';
const GROUP_ID = 'testgroup01';

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(RELAY);
    ws.binaryType = 'arraybuffer';
    ws.on('open', () => resolve(ws));
    ws.on('error', reject);
  });
}

function sendEvent(ws, ev) {
  const payload = Protocol.encodeEvent(ev);
  const frame = new Uint8Array(1 + payload.length);
  frame[0] = MsgTypeEvent;
  frame.set(payload, 1);
  ws.send(frame);
}

function sendReq(ws, req) {
  ws.send(Protocol.encodeReq(req));
}

function decodePush(bytes) {
  if (bytes[0] !== MsgTypePush) return null;
  const subIdLen = (bytes[1] << 8) | bytes[2];
  const subId = new TextDecoder().decode(bytes.subarray(3, 3 + subIdLen));
  const event = Protocol.decodeEvent(bytes.subarray(3 + subIdLen));
  return { subId, event };
}

function waitForPush(ws, subId, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.off('message', onMsg);
      reject(new Error('timeout waiting for push'));
    }, timeout);
    function onMsg(data) {
      const bytes = new Uint8Array(data);
      const push = decodePush(bytes);
      if (push && push.subId === subId) {
        clearTimeout(timer);
        ws.off('message', onMsg);
        resolve(push.event);
      }
    }
    ws.on('message', onMsg);
  });
}

function waitForEoe(ws, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout waiting for EOE')), timeout);
    function onMsg(data) {
      const text = new TextDecoder().decode(data);
      if (text.startsWith('EOE:') || text.startsWith('ERR:')) {
        clearTimeout(timer);
        ws.off('message', onMsg);
        resolve(text);
      }
    }
    ws.on('message', onMsg);
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function buildGroupEvent(privBytesA, pubA) {
  const now = Math.floor(Date.now() / 1000);
  const group = {
    groupId: GROUP_ID,
    hostPubkey: pubA,
    members: [
      { pubkey: pubA, addresses: [], joinedAt: now, isHost: true, isConnected: true },
    ],
    version: 1,
    createdAt: now,
    signature: new Uint8Array(64),
  };
  const gSig = await CryptoUtils.signMessage(privBytesA, Protocol.encodeGroupSignedData(group));
  group.signature = CryptoUtils.hexToBytes(gSig);
  const groupContent = Protocol.encodeGroup(group);

  const event = {
    transType: TransTypeGroup,
    createdAt: now,
    pubkey: pubA,
    tags: [`group:${GROUP_ID}`],
    content: groupContent,
    signature: new Uint8Array(64),
  };
  const contentSig = await CryptoUtils.signMessage(privBytesA, event.content);
  event.signature = CryptoUtils.hexToBytes(contentSig);
  return event;
}

async function main() {
  let privBytesA = CryptoUtils.hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pubA = CryptoUtils.getRawCompressedPublicKey(privBytesA);
  const groupEvent = await buildGroupEvent(privBytesA, pubA);

  console.log('== Test 1: subscriber B subscribes, no events yet -> EOE ==');
  const wsB = await connect();
  sendReq(wsB, { subId: 'b-group-sub', transType: TransTypeGroup, tagKey: 'group', tagVal: GROUP_ID });
  const eoeB = await waitForEoe(wsB);
  console.log('B EOE:', eoeB);

  console.log('== Test 2: host A posts group event -> B gets live push ==');
  const wsA = await connect();
  sendReq(wsA, { subId: 'a-group-sub', transType: TransTypeGroup, tagKey: 'group', tagVal: GROUP_ID });
  await waitForEoe(wsA);

  const pushB2Promise = waitForPush(wsB, 'b-group-sub');
  sendEvent(wsA, groupEvent);
  const pushB2 = await pushB2Promise;
  console.log('B received live push. transType=', pushB2.transType, 'tags=', pushB2.tags);
  const decoded = Protocol.decodeGroup(pushB2.content);
  console.log('Decoded group: groupId=', decoded.groupId, 'members=', decoded.members.length, 'version=', decoded.version);
  console.log('group host hex =', CryptoUtils.bytesToHex(decoded.hostPubkey).slice(0, 12));

  console.log('== Test 3: re-subscribe B -> gets stored event ==');
  wsB.close();
  await sleep(300);
  const wsB2 = await connect();
  sendReq(wsB2, { subId: 'b-group-sub2', transType: TransTypeGroup, tagKey: 'group', tagVal: GROUP_ID });
  const pushB3 = await waitForPush(wsB2, 'b-group-sub2');
  console.log('B received stored event. transType=', pushB3.transType, 'tags=', pushB3.tags);

  wsA.close();
  wsB2.close();
  console.log('\nALL TESTS PASSED');
}

main().catch((e) => {
  console.error('TEST FAILED:', e.message);
  process.exit(1);
});
