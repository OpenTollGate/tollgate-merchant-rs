use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayUrl, Tag, TagStandard};
use std::str::FromStr;
use tokio::time::Duration;


const NOSTR_S: &str = "f4be433e9648024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac5";
const CASHU_S: &str = "f4be433e9648024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac6";

#[tokio::main]
async fn main() {
    println!("Starting Tollgate - merchant");

    let nostr_keys = Keys::from_str(NOSTR_S).expect("Invalid private key");
    let client = Client::builder().signer(nostr_keys.clone()).build();

    let relay_url = "ws://127.0.0.1:8080";
    let cashu_url = "https://testnut.cashu.space";
    let nutzap_info_kind = Kind::from_u16(10019);

    let cashu_keys = Keys::from_str(CASHU_S).expect("Invalid Priv key");
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    let event = 
        EventBuilder::new(nutzap_info_kind, "")
            .tag(Tag::from_standardized_without_cell(TagStandard::Relay(RelayUrl::parse(relay_url).unwrap())))
            .tag(Tag::parse(vec!["mint", cashu_url, "sat"]).unwrap())
            .tag(Tag::parse(vec!["pubkey", &cashu_keys.public_key.to_string()]).unwrap());
    client.send_event_builder(event).await.unwrap();

    let filter = Filter::new();
    let filter = filter.authors(vec![nostr_keys.public_key]);
    let filter = filter.kind(nutzap_info_kind);
    let events = client.fetch_events(filter, Duration::from_secs(10)).await.unwrap();

    dbg!(events);
}
