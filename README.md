# Usage

`npx pcap-websocket [yourfile.pcap] [protoHandler] [tcpfilter]`

Filter a specific connection with both tcp endpoint, displaywith more readable json if payload are JSON strings

`npx pcap-websocket yourfile.pcap ws 192.168.8.247:46286,192.168.8.219:8042 | jq '. | select(.opcode == 1) | .text = (.text | fromjson)' | less`

Filter all connection on the websocket server port.

`npx pcap-websocket yourfile.pcap ws 192.168.8.219:8042`

# Known limitation
- Only a websocket handler for now, `ws`
- Do not support TCP packet reordering. Mostly work on capture on local network
- SSL not supported
