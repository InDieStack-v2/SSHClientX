use rusqlite::Connection;

pub struct ProfileRepository<'conn> {
    conn: &'conn Connection,
}

impl<'conn> ProfileRepository<'conn> {
    pub fn new(conn: &'conn Connection) -> Self {
        Self { conn }
    }

    pub fn server_name(&self, node_id: i32) -> String {
        self.conn
            .query_row("SELECT name FROM servers WHERE id = ?1", [node_id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap_or_else(|_| format!("node-{node_id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_reads_typed_server_name_and_falls_back() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE servers (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO servers (id, name) VALUES (7, 'edge')", [])
            .unwrap();
        let repository = ProfileRepository::new(&conn);
        assert_eq!(repository.server_name(7), "edge");
        assert_eq!(repository.server_name(8), "node-8");
    }
}
