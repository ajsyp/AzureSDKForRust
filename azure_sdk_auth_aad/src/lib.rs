#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
use oauth2::basic::BasicClient;
use oauth2::curl::http_client;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenUrl,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use url::Url;
mod client_helpers;
pub use client_helpers::*;
mod login_response;
pub use login_response::*;
pub mod errors;
use errors::ServerReceiveError;

#[derive(Debug)]
pub struct AuthObj {
    pub client: BasicClient,
    pub authorize_url: Url,
    pub csrf_state: CsrfToken,
    pub pkce_code_verifier: PkceCodeVerifier,
}

pub fn authorize_delegate(
    client_id: ClientId,
    client_secret: ClientSecret,
    tenant_id: &str,
    redirect_url: Url,
    resource: &str,
) -> AuthObj {
    let auth_url = AuthUrl::new(
        Url::parse(&format!(
            "https://login.microsoftonline.com/{}/oauth2/authorize",
            tenant_id
        ))
        .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse(&format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        ))
        .expect("Invalid token endpoint URL"),
    );

    // Set up the config for the Microsoft Graph OAuth2 process.
    let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        // Microsoft Graph requires client_id and client_secret in URL rather than
        // using Basic authentication.
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_url(RedirectUrl::new(redirect_url));

    // Microsoft Graph supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_extra_param("resource", resource) //"https://management.azure.com/".to_owned())
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    AuthObj {
        client,
        authorize_url,
        csrf_state,
        pkce_code_verifier,
    }
}

pub fn naive_server(
    auth_obj: &AuthObj,
    port: u32,
) -> Result<AuthorizationCode, ServerReceiveError> {
    // A very naive implementation of the redirect server.
    // A ripoff of https://github.com/ramosbugs/oauth2-rs/blob/master/examples/msgraph.rs, stripped
    // down for simplicity.
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = match request_line.split_whitespace().nth(1) {
                    Some(redirect_url) => redirect_url,
                    None => {
                        return Err(ServerReceiveError::UnexpectedRedirectUrl { url: request_line })
                    }
                };
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                println!("url == {}", url);

                let code = match url.query_pairs().find(|pair| {
                    let &(ref key, _) = pair;
                    key == "code"
                }) {
                    Some(qp) => AuthorizationCode::new(qp.1.into_owned()),
                    None => {
                        return Err(ServerReceiveError::QueryPairNotFound {
                            query_pair: "code".to_owned(),
                        })
                    }
                };

                let state = match url.query_pairs().find(|pair| {
                    let &(ref key, _) = pair;
                    key == "state"
                }) {
                    Some(qp) => CsrfToken::new(qp.1.into_owned()),
                    None => {
                        return Err(ServerReceiveError::QueryPairNotFound {
                            query_pair: "state".to_owned(),
                        })
                    }
                };

                if state.secret() != auth_obj.csrf_state.secret() {
                    return Err(ServerReceiveError::StateSecretMismatch {
                        expected_state_secret: auth_obj.csrf_state.secret().to_owned(),
                        received_state_secret: state.secret().to_owned(),
                    });
                }

                let message = "Authentication complete. You can close this window now.";
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream.write_all(response.as_bytes()).unwrap();

                // The server will terminate itself after collecting the first code.
                return Ok(code);
            }
        }
    }

    unreachable!()
}

pub fn exchange(
    auth_obj: AuthObj,
    code: AuthorizationCode,
) -> Result<
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::RequestTokenError<
        oauth2::curl::Error,
        oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    >,
> {
    // Exchange the code with a token.
    let token = auth_obj
        .client
        .exchange_code(code)
        // Send the PKCE code verifier in the token request
        .set_pkce_verifier(auth_obj.pkce_code_verifier)
        .request(http_client);

    println!("MS Graph returned the following token:\n{:?}\n", token);
    token
}
