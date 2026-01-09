use anyhow::{Result, anyhow, bail};
use libsql::{Builder, Row, Statement, params};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use ttl_cache::TtlCache;

const STATEMENTS: [&str; 4] = [
    "SELECT * FROM users WHERE id = ?1",
    "SELECT * FROM users WHERE handle = ?1",
    "INSERT INTO users (id, handle, key_content) VALUES (?1, ?2, ?3)",
    "UPDATE users SET handle = ?1, key_content = ?2 WHERE id = ?3",
];

pub struct DatabaseClient {
    statements: HashMap<String, Statement>,
    cache: Arc<Mutex<TtlCache<String, User>>>,
}

#[derive(Serialize, Clone, Debug)]
pub struct User {
    pub id: String,
    pub handle: Option<String>,
    pub key_content: String,
}

impl User {
    fn from_row(row: Row) -> Result<Self> {
        let id = row.get::<String>(0)?;
        let handle = row.get::<Option<String>>(1)?;
        let key_content = row.get::<String>(2)?;

        Ok(Self {
            id,
            handle,
            key_content,
        })
    }
}

impl DatabaseClient {
    fn statement(&self, statement: &str) -> Option<&Statement> {
        self.statements.get(statement)
    }
    pub async fn new() -> Result<Self> {
        // let database_url = std::env::var("TURSO_DATABASE_URL").expect("database url should be set");
        // let auth_token =
        //     std::env::var("TURSO_AUTH_TOKEN").expect("database auth token should be set");
        // let db = Builder::new_remote(database_url, auth_token)
        //     .build()
        //     .await?;
        let db = Builder::new_local("local.db").build().await?;
        let conn = db.connect()?;
        conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, handle TEXT UNIQUE, key_content TEXT UNIQUE NOT NULL)", ()).await?;
        let mut statements = HashMap::with_capacity(STATEMENTS.len());
        for statement in STATEMENTS {
            statements.insert(statement.to_string(), conn.prepare(statement).await?);
        }
        Ok(Self {
            statements,
            cache: Arc::new(Mutex::new(TtlCache::new(1024))),
        })
    }

    fn put_cache(&self, query: &String, user: &User) {
        self.cache.lock().insert(
            query.clone(),
            user.clone(),
            std::time::Duration::from_hours(1),
        );
    }

    fn get_cache(&self, query: &String) -> Option<User> {
        self.cache.lock().get(query).cloned()
    }

    pub async fn update_user(&self, id: &String, new_user: User) -> Result<()> {
        let statement = self
            .statement("UPDATE users SET handle = ?1, key_content = ?2 WHERE id = ?3")
            .unwrap();

        statement
            .execute(params![new_user.handle, new_user.key_content, id.clone()])
            .await
            .map_err(|e| anyhow!(e))?;

        Ok(())
    }

    pub async fn get_by_id(&self, id: &String) -> Result<Option<User>> {
        if let Some(cached) = self.get_cache(id) {
            return Ok(Some(cached));
        }
        let statement = self.statement("SELECT * FROM users WHERE id = ?1").unwrap();

        let row = statement.query([id.clone()]).await?.next().await?;
        let user = row.map(|row| User::from_row(row).unwrap());
        if let Some(user) = user {
            self.put_cache(id, &user);
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn get_by_handle(&self, handle: &String) -> Result<Option<User>> {
        if let Some(cached) = self.get_cache(handle) {
            return Ok(Some(cached));
        }

        let statement = self
            .statement("SELECT * FROM users WHERE handle = ?1")
            .unwrap();

        let row = statement.query([handle.clone()]).await?.next().await?;
        let user = row.map(|row| User::from_row(row).unwrap());

        if let Some(user) = user {
            self.put_cache(handle, &user);
            return Ok(Some(user));
        } else {
            return Ok(None);
        }
    }

    pub async fn put_user(&self, user: &User) -> Result<(), anyhow::Error> {
        let statement = self
            .statement("INSERT INTO users (id, handle, key_content) VALUES (?1, ?2, ?3)")
            .unwrap();

        let user = user.clone();
        match statement
            .execute(params![user.id, user.handle, user.key_content])
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => bail!(e),
        }
    }
}
