# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Compilation

```
dune build
```

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

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