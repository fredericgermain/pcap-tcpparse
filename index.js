#!/usr/bin/node

const pcapp = require('pcap-parser');
const { BitstreamReader, BitstreamWriter } = require('@astronautlabs/bitstream');
const { PassThrough, Writable } = require('stream');

let firstPacketHeader;
let no = 0;

const pcapFilename = process.argv[2];
const proto = process.argv[3];
const tcpFilters = process.argv[4].split(',');

let duplexIdGen = 0;
const tcpStack = {};

function getStreamDuplex(tcp) {
  const tcpStreamId = `${tcp.srcAddr}:${tcp.dstAddr}`
  const servStreamId = `${tcp.dstAddr}:${tcp.srcAddr}`
  
  const a = tcpStack[tcpStreamId];
  if (a !== undefined) { return a; }
  const n = {
    synack: false,
    index: duplexIdGen++,
    id: servStreamId,
    addrClient: tcp.dstAddr,
    streams: {
      [tcp.srcAddr]: { buffer: null },
      [tcp.dstAddr]: { buffer: null },
    },
  };
  tcpStack[tcpStreamId] = n;
  tcpStack[servStreamId] = n;
  return n;
}

const parser = pcapp.parse(pcapFilename);
parser.on('packet', function(packet) {
  no += 1;
  if (firstPacketHeader === undefined) { firstPacketHeader = packet.header };
  const pcapHeader = {
    time: (packet.header.timestampSeconds + packet.header.timestampMicroseconds/1000000) - (firstPacketHeader.timestampSeconds + firstPacketHeader.timestampMicroseconds/1000000),
    capturedLength: packet.header.capturedLength,
    originalLength: packet.header.originalLength,
  };
  let reader = new BitstreamReader();
  reader.addBuffer(packet.data);
  const mac = {};
  mac.src = (reader.readSync(48)).toString(16);
  mac.dst = (reader.readSync(48)).toString(16);
  mac.type = (reader.readSync(16));
// mac.type === 2048 => ipv4
  const ip = {};
  ip.version = reader.readSync(4);
  ip.headerLength = (reader.readSync(4)) * 4;
  ip.dsfield = reader.readSync(8);
  ip.len = reader.readSync(16);
  ip.id = reader.readSync(16);
  ip.flags = reader.readSync(16);
  if (ip.flags & 0x1) {
    ip.fragOffset = reader.readSync(16);
  }
  ip.ttl = reader.readSync(8);
  ip.proto = reader.readSync(8);
  ip.headerChecksum = reader.readSync(16);
  ip.src = Array.from(Array(4).keys()).map(() => { 
    return reader.readSync(8);
  }).join('.');
  ip.dst = Array.from(Array(4).keys()).map(() => { 
    return reader.readSync(8);
  }).join('.');
// proto === 6 => tcp
  const tcp = {};
  tcp.src = reader.readSync(16);
  tcp.dst = reader.readSync(16);
  tcp.srcAddr = `${ip.src}:${tcp.src}`;
  tcp.dstAddr = `${ip.dst}:${tcp.dst}`;
  //console.log(tcp)
  // console.log(tcpFilters.find(filt => tcp.srcAddr !== filt && tcp.dstAddr !== filt));
  if (tcpFilters && (tcpFilters.find(filt => tcp.srcAddr !== filt && tcp.dstAddr !== filt) !== undefined) ) {
    return;
  } 
  tcp.seqNum = reader.readSync(32);
  tcp.ackNum = reader.readSync(32);
  tcp.headerLen = reader.readSync(4);
  tcp.flags = reader.readSync(12); // 2: syn
  tcp.windowSize = reader.readSync(16);
  tcp.checksum = reader.readSync(16);
  tcp.urgentPtr = reader.readSync(16);
  const optionsByteLen = tcp.headerLen * 4 - 20;
  tcp.options = Buffer.alloc(optionsByteLen);
  packet.data.copy(tcp.options, 0, reader.offset / 8, reader.offset / 8 + optionsByteLen);
//  reader.skip(optionsByteLen * 8);
  let tcpPayload;
  if (reader.available > optionsByteLen * 8) {
    // reader is q little buggy/unintuivice
    reader.offset = reader.offset + optionsByteLen * 8;
    reader.skip(optionsByteLen * 8);
    const byteLen = reader.available / 8;
//console.log('len', byteLen)
    tcpPayload = Buffer.alloc(byteLen);
    packet.data.copy(tcpPayload, 0, reader.offset / 8, reader.offset / 8 + byteLen);
  }
  const tcpPayloadLength = tcpPayload === undefined ? 0 : tcpPayload.length;
  const parsedPacket = {
    no,
    pcapHeader,
    mac,
    ip,
    tcp,
    tcpPayloadLength,
  };
  //console.log(parsedPacket);
   // console.log(tcpPayload);

  const streamDuplex = getStreamDuplex(tcp);
  if (streamDuplex.synack === false) {
    streamDuplex.synack = true;
    return;
  }
  if (tcpPayload === undefined) {
    return;
  }
  const buf = streamDuplex.streams[tcp.srcAddr].buffer;
  if (buf === null || buf.length === 0) {
    streamDuplex.streams[tcp.srcAddr].buffer = tcpPayload;
  } else {
    streamDuplex.streams[tcp.srcAddr].buffer = Buffer.concat([streamDuplex.streams[tcp.srcAddr].buffer, tcpPayload]);
  }
  if (proto === 'ws') {
    parseWS(streamDuplex, parsedPacket);
  } else {
    streamDuplex.streams[tcp.srcAddr].buffer = null;
  }
});

const WS_STATES = {
  HTTP_REQ: 0,
  HTTP_RESP: 1,
  WS: 2,
};

function parseWS(streamDuplex, parsedPacket) {
  const { pcapHeader, tcp } = parsedPacket;
  const streamPayload = streamDuplex.streams[tcp.srcAddr].buffer;
  if (streamDuplex.state === undefined) {
    const httpReq = streamPayload.toString('utf8');
    console.log(JSON.stringify({
      time: pcapHeader.time,
      connIdx: streamDuplex.index,
      connId: streamDuplex.id,
      state: 'http',
      httpReq,
    }));
    streamDuplex.state = WS_STATES.HTTP_RESP;
    streamDuplex.streams[tcp.srcAddr].buffer = null;
  } else if (streamDuplex.state === WS_STATES.HTTP_RESP) {
    const httpResp = streamPayload.toString('utf8');
    console.log(JSON.stringify({
      time: pcapHeader.time,
      connIdx: streamDuplex.index,
      connId: streamDuplex.id,
      state: 'http',
      httpResp,
    }));
    streamDuplex.state = WS_STATES.WS;
    streamDuplex.streams[tcp.srcAddr].buffer = null;
  } else if (streamDuplex.state === WS_STATES.WS && streamPayload) {
    let streamPayloadOffset = 0;
    let frameCount = 0;
    while (streamPayloadOffset < streamPayload.length) {
// console.log(streamPayloadOffset, streamPayload.length - streamPayloadOffset, streamPayload.length)
      const wsFrameBuffer = Buffer.alloc(streamPayload.length - streamPayloadOffset);
      streamPayload.copy(wsFrameBuffer, 0, streamPayloadOffset, streamPayload.length);
      const { frame, length, error } = parseWebsocketFrame(wsFrameBuffer);
      if (error === 'not_enough_data') {
        streamDuplex.streams[tcp.srcAddr].buffer = wsFrameBuffer;
        break;
      }
      console.log(JSON.stringify({
        time: pcapHeader.time,
        connIdx: streamDuplex.index,
        connId: streamDuplex.id,
        dir: tcp.srcAddr === streamDuplex.addrClient ? 'c2s' : 's2c',
        state: 'ws',
        opcode: frame.opcode,
        text: (frame.opcode === 1) ? frame.utf8Payload : undefined,
      }));
      streamPayloadOffset += length;
      frameCount += 1;
    }
    if (streamPayloadOffset === streamPayload.length) {
      streamDuplex.streams[tcp.srcAddr].buffer = null;
    }
  }
}

function parseWebsocketFrame(tcpPayload) {
    const reader = new BitstreamReader();
    reader.addBuffer(tcpPayload);
    const ws = {
    };
    ws.fin = reader.readSync(1);
    ws.priv3 = reader.readSync(3);
    ws.opcode = reader.readSync(4);
    if (ws.opcode === 4) { // not sure what is is, from an android stack
      ws.opcode4 = reader.readSync(8);
      return { frame: ws, length: 2 };
    }
    ws.mask = reader.readSync(1);
    ws.payloadLen7 = reader.readSync(7);
    if (ws.payloadLen7 < 126) {
      ws.payloadLen = ws.payloadLen7;
    } else if (ws.payloadLen7 == 126) {
      ws.payloadLen16 = reader.readSync(16);
      ws.payloadLen = ws.payloadLen16;
    } else if (ws.payloadLen7 == 127) {
      throw new Error('untested_ws_size');
    }
//    ws.zero8 = reader.readSync(8);
    if (ws.mask) {
      ws.maskingKey = reader.readSync(32);
    }
    const byteLen = reader.available / 8;
    if (byteLen > ws.payloadLen) {
// there are several ws frame in tcp payload
    } else if (byteLen < ws.payloadLen) {
      //console.error(ws);
     //throw new Error(`not_enough_data got:${byteLen} expected:${ws.payloadLen}`);
      return { length: 0, error: 'not_enough_data' };
    }
    ws.rawPayload = Buffer.alloc(ws.payloadLen);
    tcpPayload.copy(ws.rawPayload, 0, reader.offset / 8, reader.offset / 8 + ws.payloadLen);
    if (ws.mask) {
      ws.unmaskedPayload = Buffer.alloc(ws.payloadLen);
      const pass = new PassThrough();
      const writer = new BitstreamWriter(pass, ws.payloadLen);
      const reader = new BitstreamReader();
      reader.addBuffer(ws.rawPayload);
      pass.on('data', (b) => {
        ws.payload = b;
      });
      // js no xor...
      let maskoffset = 0;
      const bitLength = reader.offset + 8 * ws.payloadLen;
      // console.log(ws.maskingKey.toString(16));
      while (reader.offset < bitLength) {
        const i = reader.readSync(1);
        const j = (ws.maskingKey >> (31-maskoffset)) % 2;
        const xor = ( i && !j ) || ( !i && j ) ? 1 :0;
        // console.log(i, j, xor)
        writer.write(1, xor);
        if (maskoffset === 31) {
          maskoffset = 0;
        } else {
          maskoffset += 1;
        }
      }
    } else {
      ws.payload = ws.rawPayload;
    }
    if (ws.opcode === 1) { // text
      try {
        ws.utf8Payload = ws.payload.toString('utf8');
      } catch (e) {
      }
    } else if (ws.opcode === 8) { // close
     //payload may be close reason
    } else if (ws.opcode === 9) { // ping
      if (ws.payloadLen) {
        console.error(ws);
        throw new Error('opcode_not_supported');
      }
    } else if (ws.opcode === 10) { // pong
      if (ws.payloadLen) {
        console.error(ws);
        throw new Error('opcode_not_supported');
      }
    } else {
      console.error(ws);
      throw new Error('opcode_not_supported');
    }
  return { frame: ws, length: reader.offset / 8 + ws.payloadLen };
}
