use thiserror::Error;

#[derive(Debug, Error)]
pub enum GommageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid glob pattern {pattern:?}: {source}")]
    Glob {
        pattern: String,
        #[source]
        source: globset::Error,
    },

    #[error("invalid regex {pattern:?}: {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("signature verification failed")]
    BadSignature,

    #[error("picto {id} is {reason}")]
    PictoUnusable { id: String, reason: &'static str },

    #[error("invalid picto: {0}")]
    InvalidPicto(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("mapper error: {0}")]
    Mapper(String),
}
