mod client;
mod protocol;
mod server;

pub use client::{get_aws_credentials, get_secret, start_aws_login};
pub use server::{RequestServer, begin_aws_login};
