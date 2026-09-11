type == "object" and
keys == ["data_uuid", "installation_id", "layout"] and
.layout == 1 and
(.installation_id | type == "string" and length > 0 and length <= 128) and
(.data_uuid | ascii_downcase) == ($uuid | ascii_downcase)
