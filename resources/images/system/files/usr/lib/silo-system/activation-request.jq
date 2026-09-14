type == "object" and
keys == ["data_layout", "data_uuid", "required_shares", "schema"] and
.schema == 1 and .data_layout == 1 and
(.data_uuid | type == "string" and test("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")) and
(.required_shares | type == "array" and length <= 64) and
all(.required_shares[];
    type == "object" and keys == ["path", "tag", "writable"] and
    (.path | type == "string" and startswith("/") and length <= 4096 and test("^[^\u0000-\u001f]+$")) and
    (.tag | type == "string" and length > 0 and length <= 255 and test("^[^\u0000-\u001f]+$")) and
    (.writable | type == "boolean"))
