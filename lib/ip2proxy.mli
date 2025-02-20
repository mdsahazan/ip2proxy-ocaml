module Database :
  sig
    type meta_data = {
      fs : in_channel;
      db_type : int;
      db_column : int;
      db_year : int;
      db_month : int;
      db_day : int;
      ipv4_db_count : Stdint.uint32;
      ipv4_base_addr : Stdint.uint32;
      ipv6_db_count : Stdint.uint32;
      ipv6_base_addr : Stdint.uint32;
      ipv4_index_base_addr : Stdint.uint32;
      ipv6_index_base_addr : Stdint.uint32;
      ipv4_column_size : Stdint.uint32;
      ipv6_column_size : Stdint.uint32;
    }
    type ip2proxy_record = {
      country_short : string;
      country_long : string;
      region : string;
      city : string;
      isp : string;
      proxy_type : string;
      is_proxy : int;
      domain : string;
      usage_type : string;
      asn : string;
      asys : string;
      last_seen : int;
      threat : string;
      provider : string;
      fraud_score : string;
    }
    exception Ip2proxy_exception of string
    val get_api_version : string
    val open_db : string -> meta_data
    val close_db : meta_data -> unit
    val query : meta_data -> string -> ip2proxy_record
  end
