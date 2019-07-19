use crate::errors::UnexpectedStatusCodeError;
use crate::LoginResponse;
use failure::Error;
use futures::future::{done, err, ok, Either};
use http::status::StatusCode;
use hyper::rt::{Future, Stream};
use hyper::{Body, Client, Request};
use std::sync::Arc;
use url::form_urlencoded;

fn check_status_extract_body(
    resp: hyper::Response<Body>,
    expected_status: StatusCode,
) -> impl Future<Item = String, Error = Error> {
    if resp.status() != expected_status {
        Either::A(
            err(UnexpectedStatusCodeError {
                expected: expected_status,
                received: resp.status(),
            })
            .from_err(),
        )
    } else {
        Either::B(resp.into_body().concat2().from_err().and_then(move |body| {
            done(String::from_utf8(body.to_vec()))
                .from_err()
                .and_then(|s| {
                    println!("body: {}", s);
                    ok(s.to_owned())
                })
        }))
    }
}

pub fn perform_http_request(
    client: &Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    req: Request<Body>,
    expected_status: StatusCode,
) -> impl Future<Item = String, Error = Error> {
    println!("req == {:?}", req);
    client
        .request(req)
        .from_err()
        .and_then(move |res| check_status_extract_body(res, expected_status))
}

pub fn authorize_non_interactive(
    client: Arc<Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>>,
    //  grant_type: &str, fixed on "client_credentials",
    client_id: &oauth2::ClientId,
    client_secret: &oauth2::ClientSecret,
    resource: &str,
    tenant_id: &str,
) -> impl Future<Item = LoginResponse, Error = Error> {
    let encoded: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .append_pair("client_id", client_id.as_str())
        .append_pair("client_secret", client_secret.secret())
        .append_pair("resource", resource)
        .finish();

    let uri = format!(
        "https://login.microsoftonline.com/{}/oauth2/token",
        tenant_id
    );

    //let client = Arc::clone(client);

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
            done(LoginResponse::from_str(&resp))
                .from_err()
                .and_then(|r| {
                    println!("{:?}", r);
                    ok(r)
                })
        })
    })
}
