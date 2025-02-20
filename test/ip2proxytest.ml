(* open Printf *)
(* open Ip2proxy *)

(* (* query IP2Proxy BIN datababase *) *)
(* (* let meta = Database.open_db "./IP2PROXY-LITE-PX1.BIN";; *) *)

(* let mylist = ["3.91.171.8"; "37.252.228.50"; "197.85.191.64"];; *)

(* let getprox ip = *)
	(* let res = Database.query meta ip in *)
	(* printf "IP: %s\n" ip; *)
	(* printf "country_short: %s\n" res.country_short; *)
	(* printf "country_long: %s\n" res.country_long; *)
	(* printf "region: %s\n" res.region; *)
	(* printf "city: %s\n" res.city; *)
	(* printf "isp: %s\n" res.isp; *)
	(* printf "proxy_type: %s\n" res.proxy_type; *)
	(* printf "is_proxy: %d\n" res.is_proxy; *)
	(* printf "domain: %s\n" res.domain; *)
	(* printf "usage_type: %s\n" res.usage_type; *)
	(* printf "asn: %s\n" res.asn; *)
	(* printf "as: %s\n" res.asys; *)
	(* printf "last_seen: %d\n" res.last_seen; *)
	(* printf "threat: %s\n" res.threat; *)
	(* printf "provider: %s\n" res.provider; *)
	(* printf "fraud_score: %s\n" res.fraud_score; *)
	(* printf "=======================================================================\n";; *)


(* List.iter getprox mylist;; *)

(* Database.close_db meta;; *)

print_endline "Unable to embed PX1 LITE BIN as GitHub complaining the file too large, hence this test code needs to be commented out.\n"