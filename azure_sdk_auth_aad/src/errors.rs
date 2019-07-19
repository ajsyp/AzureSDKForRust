use http::status::StatusCode;

#[derive(Debug, Clone, Fail)]
#[fail(
    display = "invalid status code received. Expected: {}, received: {}",
    expected, received
)]
pub struct UnexpectedStatusCodeError {
    pub expected: StatusCode,
    pub received: StatusCode,
}

#[derive(Debug, Fail)]
pub enum ServerReceiveError {
    #[fail(display = "unexpected redirect url: {}", url)]
    UnexpectedRedirectUrl { url: String },
    #[fail(display = "query pair not found: {}", query_pair)]
    QueryPairNotFound { query_pair: String },
    #[fail(
        display = "State secret mismatch: expected {}, recieved: {}",
        expected_state_secret, received_state_secret
    )]
    StateSecretMismatch {
        expected_state_secret: String,
        received_state_secret: String,
    },
}
