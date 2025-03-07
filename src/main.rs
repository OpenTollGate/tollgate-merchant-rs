use bytes::{Buf, Bytes};
use cdk::amount::SplitTarget;
use cdk::nuts::{CurrencyUnit, MintQuoteState, Proof, PublicKey, SecretKey, SpendingConditions};
use cdk::wallet::client;
use cdk::Amount;
use cdk::{cdk_database::WalletMemoryDatabase, wallet::Wallet, Error};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::{header, Method, StatusCode};
use hyper_util::rt::TokioIo;
use nostr_database::Events;
use nostr_sdk::{
    Alphabet, Client, EventBuilder, Filter, Keys, Kind, RelayUrl, SingleLetterTag, Tag, TagStandard,
};
use std::net::SocketAddr;
use std::vec;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use std::convert::Infallible;
use serde::{Serialize, Deserialize};

const NOSTR_S: &str = "f4be433e9208024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac5";
const CNOSTR_S: &str = "f4be430e9208024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac5";
const MERCHANT_CASHU_SECRET: &str =
    "f4be433e9648024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac6";
const USER_CASHU_SECRET: &str = "a4be433e9648024b8d3ce6ab4898f0b8bfd87c3344a633a72af0fbdc6c352ac6";
const RELAY_URL: &str = "ws://127.0.0.1:8080";
const CASHU_URL: &str = "https://testnut.cashu.space";
static NOTFOUND: &[u8] = b"Not Found";

fn nutzap_info_kind() -> Kind {
    Kind::from_u16(10019)
}

fn get_keys(secret: &str) -> Keys {
    Keys::from_str(secret).expect("Invalid private key")
}

async fn get_nutzap_info(client: &Client) -> Events {
    let nostr_keys = get_keys(NOSTR_S);
    let filter = Filter::new();
    let filter = filter.authors(vec![nostr_keys.public_key]);
    let filter = filter.kind(nutzap_info_kind());
    client
        .fetch_events(filter, Duration::from_secs(10))
        .await
        .unwrap()
}

async fn publish_nutzap_info(client: &Client) {
    let events = get_nutzap_info(client).await;
    if events.len() > 0 {
        println!("nutzap info already exists");
        return;
    }

    let cashu_keys = get_keys(MERCHANT_CASHU_SECRET);
    let event = EventBuilder::new(nutzap_info_kind(), "")
        .tag(Tag::from_standardized_without_cell(TagStandard::Relay(
            RelayUrl::parse(RELAY_URL).unwrap(),
        )))
        .tag(Tag::parse(vec!["mint", CASHU_URL, "sat"]).unwrap())
        .tag(Tag::parse(vec!["pubkey", &cashu_keys.public_key.to_string()]).unwrap());
    client.send_event_builder(event).await.unwrap();
}

async fn make_nutzap_payment(client: &Client) {
    let events = get_nutzap_info(client).await;
    let nutzap_info_event = events.first().unwrap();
    let tags = &nutzap_info_event.tags;
    let mut tag_values = HashMap::new();

    for tag in tags.clone().into_iter() {
        let buf = tag.to_vec();
        tag_values.insert(buf[0].clone(), buf[1..].to_vec());
    }
    let mint_info: &[_] = &tag_values["mint"];
    let mint_url: &str = &mint_info[0];
    let mint_unit: &str = &mint_info[1];
    let merchant_pubkey: &str = &tag_values["pubkey"][0];
    let merchant_pubkey = PublicKey::from_str(&format!("02{merchant_pubkey}")).unwrap();
    let relay_url: &str = &tag_values["relay"][0];

    let user_walet = Wallet::new(
        mint_url,
        CurrencyUnit::from_str(mint_unit).unwrap(),
        Arc::new(WalletMemoryDatabase::default()),
        &hex::decode(USER_CASHU_SECRET).unwrap(),
        None,
    )
    .unwrap();

    let amount = Amount::from(1_000);
    let quote = user_walet.mint_quote(amount, None).await.unwrap();

    println!("Minting tokens to p2pk");
    loop {
        let status = user_walet.mint_quote_state(&quote.id).await.unwrap();

        if status.state == MintQuoteState::Paid {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    let receive_amount = user_walet
        .mint(
            &quote.id,
            SplitTarget::default(),
            Some(SpendingConditions::P2PKConditions {
                data: merchant_pubkey,
                conditions: None,
            }),
        )
        .await
        .unwrap();

    println!("Publishing to nostr");
    let cnostr_keys = get_keys(CNOSTR_S);

    // sending the nutzap event
    let event = EventBuilder::new(Kind::Custom(9321), "Tollgate payment")
        .tag(
            Tag::parse(vec![
                "proof",
                &serde_json::to_string(&receive_amount[0]).unwrap(),
            ])
            .unwrap(),
        )
        .tag(Tag::parse(vec!["u", mint_url]).unwrap())
        .tag(Tag::parse(vec!["e", &nutzap_info_event.id.to_string(), relay_url]).unwrap())
        .tag(Tag::parse(vec!["p", &nutzap_info_event.pubkey.to_string()]).unwrap())
        .tag(Tag::parse(vec!["d", &cnostr_keys.public_key.to_string()]).unwrap());
    // d tag is used to identify the payment of the user
    client.send_event_builder(event).await.unwrap();
}

async fn verify_payment(user_mac_address: &str) -> Result<Amount, Error> {
    let client = get_nostr_client(NOSTR_S).await;
    let nostr_keys = get_keys(NOSTR_S);
    let filter = Filter::new()
        .kind(Kind::Custom(9321))
        .custom_tag(
            SingleLetterTag {
                character: Alphabet::P,
                uppercase: false,
            },
            nostr_keys.public_key,
        )
        .custom_tag(
            SingleLetterTag {
                character: Alphabet::D,
                uppercase: false,
            },
            user_mac_address,
        );
    let events = client
        .fetch_events(filter, Duration::from_secs(4))
        .await
        .unwrap();

    let mut proof: Option<Proof> = None;
    for event in events.into_iter() {
        for tag in event.tags.into_iter() {
            let words = tag.to_vec();
            if words[0] == "proof".to_owned() {
                proof = serde_json::from_str(&words[1]).unwrap();
            }
        }
    }

    let wallet = Wallet::new(
        CASHU_URL,
        CurrencyUnit::from_str("sat").unwrap(),
        Arc::new(WalletMemoryDatabase::default()),
        &hex::decode(MERCHANT_CASHU_SECRET).unwrap(),
        None,
    )
    .unwrap();
    let proof = proof.unwrap();
    wallet
        .receive_proofs(
            vec![proof],
            SplitTarget::None,
            &[SecretKey::from_hex(MERCHANT_CASHU_SECRET).unwrap()],
            &[],
        )
        .await
}

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, GenericError>;

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Deserialize)]
struct NotifyPaymentRequestPayload {
    user_mac_address: String,
}

#[derive(Serialize)]
struct NotifyPaymentResponsePayload {
    amount: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

type ResponseResult = Result<Response<BoxBody>, GenericError>;
async fn notify_paynent(req: Request<IncomingBody>) -> ResponseResult {
    // Aggregate the body...
    let whole_body = req.collect().await?.aggregate();
    // Decode as JSON...

    let data: NotifyPaymentRequestPayload = match serde_json::from_reader(whole_body.reader()) {
        Ok(payload) => payload,
        Err(_) => {
            let error_response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(full(
                    serde_json::to_string(&ErrorResponse {
                        error: "Invalid request payload".to_string(),
                    })?,
                ))?;
            return Ok(error_response);
        }
    };

    match verify_payment(&data.user_mac_address).await  {
        Ok(amount) => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(full(serde_json::to_string(&NotifyPaymentResponsePayload {amount: amount.into()})? ))?;
            Ok(response)
        },
        Err(err) => {
            let error_response = Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED) // HTTP 402 for failed payments
                .header(header::CONTENT_TYPE, "application/json")
                .body(full(
                    serde_json::to_string(&ErrorResponse {
                        error: format!("Payment failed: {}", err),
                    })?,
                ))?;
            Ok(error_response)
        }
    }

}

async fn root(req: Request<IncomingBody>) -> ResponseResult {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/notify_payment") => notify_paynent(req).await,
        _ => {
            // Return 404 not found response.
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full(NOTFOUND))
                .unwrap())
        }
    }
}

async fn get_nostr_client(key: &str) -> Client {
    let nostr_keys = get_keys(key);
    let client = Client::builder().signer(nostr_keys.clone()).build();
    client.add_relay(RELAY_URL).await.unwrap();
    client.connect().await;
    client
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // publish nutzap event

    let client = &get_nostr_client(NOSTR_S).await;
    println!("Receiver publishes their nutzapp info");
    publish_nutzap_info(client).await;

    let addr = SocketAddr::from(([127, 0, 0, 1], 5122));

    // We create a TcpListener and bind it to 127.0.0.1:3000
    let listener = TcpListener::bind(addr).await?;

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(root))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
