use cdk::amount::SplitTarget;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PublicKey, SpendingConditions, Proof};
use cdk::Amount;
use cdk::{cdk_database::WalletMemoryDatabase, wallet::Wallet};
use nostr_database::Events;
use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayUrl, Tag, TagStandard, SingleLetterTag, Alphabet};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::time::{sleep, Duration};

const NOSTR_S: &str = "f4be433e9208024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac5";
const CNOSTR_S: &str = "f4be430e9208024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac5";
const MERCHANT_CASHU_SECRET: &str =
    "f4be433e9648024b8d3ce6ab4798f0b8bfd87c3344a633a72af0fbdc6c352ac6";
const USER_CASHU_SECRET: &str = "a4be433e9648024b8d3ce6ab4898f0b8bfd87c3344a633a72af0fbdc6c352ac6";
const RELAY_URL: &str = "ws://127.0.0.1:8080";
const CASHU_URL: &str = "https://testnut.cashu.space";

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
        dbg!(&events);
        return;
    }

    let cashu_keys = get_keys(MERCHANT_CASHU_SECRET);
    let event = EventBuilder::new(nutzap_info_kind(), "")
        .tag(Tag::from_standardized_without_cell(TagStandard::Relay(
            RelayUrl::parse(RELAY_URL).unwrap(),
        )))
        .tag(Tag::parse(vec!["mint", CASHU_URL, "sat"]).unwrap())
        .tag(Tag::parse(vec!["pubkey", &cashu_keys.public_key.to_string()]).unwrap());
    dbg!(&event);
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
    
    // sending the nutzap event
    let event = EventBuilder::new(Kind::Custom(9321), "Tollgate payment")
        .tag(Tag::parse(vec!["proof", &serde_json::to_string(&receive_amount[0]).unwrap()]).unwrap())
        .tag(Tag::parse(vec!["u", mint_url]).unwrap())
        .tag(Tag::parse(vec!["e", &nutzap_info_event.id.to_string(), relay_url]).unwrap())
        .tag(Tag::parse(vec!["p", &nutzap_info_event.pubkey.to_string()]).unwrap());
    client.send_event_builder(event).await.unwrap();
}

async fn verify_payment(client: &Client) {
    let nostr_keys = get_keys(NOSTR_S);
    let filter = Filter::new()
        .kind(Kind::Custom(9321))
        .custom_tag(SingleLetterTag { character: Alphabet::P, uppercase: false }, nostr_keys.public_key);
    let events = client.fetch_events(filter, Duration::from_secs(4)).await.unwrap();
    dbg!(&events);

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
    wallet.swap(None, SplitTarget::None, vec![proof.unwrap()], None, true).await.unwrap();
    println!("received the payment");
    println!("Updated balance {:?}", wallet.total_balance().await);
}

#[tokio::main]
async fn main() {
    println!("Tollgate merchant setup");

    let nostr_keys = get_keys(NOSTR_S);
    let client = &Client::builder().signer(nostr_keys.clone()).build();
    client.add_relay(RELAY_URL).await.unwrap();
    client.connect().await;

    publish_nutzap_info(client).await;

    println!("User retrives nutzap information to make payment");
    let cnostr_keys = get_keys(CNOSTR_S);
    let cclient = &Client::builder().signer(cnostr_keys.clone()).build();
    cclient.add_relay(RELAY_URL).await.unwrap();
    cclient.connect().await;
    make_nutzap_payment(cclient).await;

    println!("Merchant Verifies payment");
    verify_payment(client).await;
}
