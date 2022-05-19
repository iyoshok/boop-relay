# Protocol

## Connect
Input: `CONNECT <key> <password>\n`

Response:
- correct login data: `HEY\n`
- incorrect / key doesn't exist `NO\n`

## Disconnect
Input: `DISCONNECT\n`

## Ping
Used to determine whether the server is still listening and the client is still active

Input `PING\n`

Response:`PONG\n`

## Boop - to Server
The main functionality

Input `BOOP <target_partner_key>\n`

## Boop - to Client

Input `BOOP <source_parter_key>\n`

## Online Check
Checks if the partner is online

Input `AYT <partner_key>\n`

Response:
- partner online: `ONLINE <partner_key>\n`
- partner offline: `AFK <partner_key>\n`

## Other Errors
Command text is malformed: `ERROR MALFORMED_COMMAND\n`
Command arguments are malformed / missing: `ERROR MALFORMED_ARGUMENTS\n`
WrongOrder: `ERROR PROTOCOL_MISMATCH\n`