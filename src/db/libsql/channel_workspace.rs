//! Channel workspace storage implementation for LibSqlBackend.

use async_trait::async_trait;
use libsql::params;

use super::{LibSqlBackend, fmt_ts, get_text};
use crate::db::ChannelWorkspaceDbStore;
use crate::error::DatabaseError;

use chrono::Utc;

#[async_trait]
impl ChannelWorkspaceDbStore for LibSqlBackend {
    async fn channel_workspace_read(
        &self,
        channel_id: &str,
        key: &str,
    ) -> Result<Option<String>, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT value FROM channel_workspace WHERE channel_id = ?1 AND key = ?2",
                params![channel_id, key],
            )
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        match rows
            .next()
            .await
            .map_err(|e| DatabaseError::Query(e.to_string()))?
        {
            Some(row) => Ok(Some(get_text(&row, 0))),
            None => Ok(None),
        }
    }

    async fn channel_workspace_write(
        &self,
        channel_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.connect().await?;
        let now = fmt_ts(&Utc::now());
        conn.execute(
            "INSERT INTO channel_workspace (channel_id, key, value, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (channel_id, key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = ?4",
            params![channel_id, key, value, now],
        )
        .await
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
        Ok(())
    }

}
