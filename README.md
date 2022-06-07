# BOOP Server
**Disclaimer:** This project is the result of a personal coding excercise with the goal of improving my familiarity with the [Tauri application framework](https://tauri.studio). 
This means that I knowingly ignored best practices in software, protocol and interface design, and avoided safety guardrails, if necessary, to speed up the
developement process. I don't intend on actively developing this system any further. However, if you want to contribute to this project, feel free to submit
pull requests or open issues, I will try to reply to them as quickly as possible. 

## BOOP
- Server: <- You are here
- Client: https://github.com/iyoshok/boop-snoot

This repository contains the server code for the BOOP server application. All hints for using the client application are in the respective repository (see above). This document will quickly explain how to host your very own BOOP server:

### TL;DR
1. Get a TLS certificate for your domain and save them in PEM format.
2. Ask your friends / partners / colleagues for their desired username and a Argon2id hash of their desired password and save this data to a JSON file (the JSON schema is demonstrated in `clients.json`). The filename doesn't matter, the schema does.
3. Run `boop-relay <path to clients file, e.g. clients.json> <socket address, e.g. localhost:1234> -k <path to cert private key> -c <path to cert file>`. All of these arguments are necessary, if you omit any, the application will exit immediately.

### In Depth
TODO
