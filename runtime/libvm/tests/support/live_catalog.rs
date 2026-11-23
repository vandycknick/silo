// Logical catalog evidence, read through SQLite rather than raw inode handles.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use sqlx::{AssertSqlSafe, Connection, Row, SqliteConnection};

#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    schema: Vec<Vec<String>>,
    tables: BTreeMap<String, Vec<Vec<String>>>,
}

fn identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub async fn snapshot(home: &Path) -> Snapshot {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(home.join("state.db"))
        .read_only(true)
        .create_if_missing(false)
        .busy_timeout(Duration::from_secs(2));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("read existing catalog through SQLx");
    sqlx::query("PRAGMA query_only = ON")
        .execute(&mut connection)
        .await
        .expect("logical evidence is query-only");
    let mut transaction = connection.begin().await.expect("catalog read snapshot");
    let schema = sqlx::query("SELECT quote(type), quote(name), quote(tbl_name), quote(sql) FROM sqlite_schema ORDER BY type, name")
        .fetch_all(&mut *transaction)
        .await
        .expect("read complete catalog schema")
        .into_iter()
        .map(|row| (0..4).map(|column| row.get::<String, _>(column)).collect())
        .collect();
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .fetch_all(&mut *transaction)
            .await
            .expect("read catalog tables");
    let mut tables = BTreeMap::new();
    for name in names {
        // Identifiers come from SQLite's schema and are double-quote escaped;
        // neither statement interpolates SQL values.
        let columns = sqlx::query(AssertSqlSafe(format!(
            "PRAGMA table_info({})",
            identifier(&name)
        )))
        .fetch_all(&mut *transaction)
        .await
        .expect("read table columns");
        let expressions: Vec<String> = columns
            .iter()
            .map(|column| {
                let column = identifier(column.get::<&str, _>("name"));
                format!("typeof({column}) || ':' || hex({column})")
            })
            .collect();
        let statement = format!(
            "SELECT {} FROM {}",
            expressions.join(", "),
            identifier(&name)
        );
        let mut rows: Vec<Vec<String>> = sqlx::query(AssertSqlSafe(statement))
            .fetch_all(&mut *transaction)
            .await
            .expect("read every logical catalog value")
            .into_iter()
            .map(|row| {
                (0..expressions.len())
                    .map(|column| row.get::<String, _>(column))
                    .collect()
            })
            .collect();
        rows.sort();
        tables.insert(name, rows);
    }
    transaction
        .commit()
        .await
        .expect("finish catalog read snapshot");
    connection
        .close()
        .await
        .expect("close logical evidence reader");
    Snapshot { schema, tables }
}
