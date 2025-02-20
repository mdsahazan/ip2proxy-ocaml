# IP2Proxy OCaml Module

This OCaml module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN). It supports both IP address in IPv4 and IPv6.

## Compilation

```
dune build
```

## QUERY USING THE BIN FILE

## Dependencies

This module requires IP2Proxy BIN data file to function. You may download the BIN data file at
* IP2Proxy LITE BIN Data (Free): https://lite.ip2location.com
* IP2Proxy Commercial BIN Data (Comprehensive): https://www.ip2location.com

## Methods

Below are the methods supported in this module.

|Method Name|Description|
|---|---|
|open_db|Initialize with the BIN file.|
|query|Returns the proxy information.|
|close_db|Closes BIN file.|

## Usage

```ocaml
open Printf
open Ip2proxy

(* query IP2Proxy BIN datababase *)
let meta = Database.open_db "/path_to_your_database_file/your_BIN_file.BIN";;

let ip = "8.8.8.8";;
let res = Database.query meta ip;;

printf "country_short: %s\n" res.country_short;;
printf "country_long: %s\n" res.country_long;;
printf "region: %s\n" res.region;;
printf "city: %s\n" res.city;;
printf "isp: %s\n" res.isp;;
printf "proxy_type: %s\n" res.proxy_type;;
printf "is_proxy: %d\n" res.is_proxy;;
printf "domain: %s\n" res.domain;;
printf "usage_type: %s\n" res.usage_type;;
printf "asn: %s\n" res.asn;;
printf "as: %s\n" res.asys;;
printf "last_seen: %d\n" res.last_seen;;
printf "threat: %s\n" res.threat;;
printf "provider: %s\n" res.provider;;
printf "fraud_score: %s\n" res.fraud_score;;

Database.close_db meta;;

```
