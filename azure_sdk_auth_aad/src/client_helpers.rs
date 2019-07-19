use crate::LoginResponse;
use azure_sdk_core::errors::{check_status_extract_body_2, AzureError};
use futures::future::{done, ok};
use http::status::StatusCode;
use hyper::rt::Future;
use hyper::{Body, Client, Request};
use std::sync::Arc;
use url::form_urlencoded;

pub fn perform_http_request(
    client: &Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    req: Request<Body>,
    expected_status: StatusCode,
) -> impl Future<Item = String, Error = AzureError> {
    println!("req == {:?}", req);
    client
        .request(req)
        .from_err()
        .and_then(move |res| check_status_extract_body_2(res, expected_status))
}

pub fn authorize_non_interactive(
    client: Arc<Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>,
    //  grant_type: &str, fixed on "client_credentials",
    client_id: &oauth2::ClientId,
    client_secret: &oauth2::ClientSecret,
    resource: &str,
    tenant_id: &str,
) -> impl Future<Item = LoginResponse, Error = AzureError> {
    let encoded: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", client_id.as_str())
        .append_pair("client_secret", client_secret.secret())
        .append_pair("resource", resource)
        .finish();

    let uri = format!("https://login.microsoftonline.com/{}/oauth2/token", tenant_id);

    done(
        Request::builder()
            .method("POST")
            .header("ContentType", "Application / WwwFormUrlEncoded")
            .uri(uri)
            .body(Body::from(encoded)),
    )
    .from_err()
    .and_then(move |request| {
        perform_http_request(&client, request, StatusCode::OK).and_then(|resp| {
            done(LoginResponse::from_str(&resp)).from_err().and_then(|r| {
                println!("{:?}", r);
                ok(r)
            })
        })
    })
}
