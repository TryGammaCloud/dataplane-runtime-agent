//! Process-backed sessions. Creation is authorized by the server and delegated to the sandbox manager.
//! No session is allocated merely because an environment identity exists.
pub use crate::terminal::Terminals as SessionManager;
