mod database;

use actix_web::{App, HttpResponse, HttpServer, Responder, get, http::header, post, put, web};
use anyhow::{Result, anyhow, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{AeadMut, OsRng, rand_core::RngCore},
};
use database::DatabaseClient;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{str::FromStr, sync::Arc};

use crate::database::User;

struct AppState {
    secret_key: [u8; 32],
    db: Arc<DatabaseClient>,
}

enum WildcardRecipient {
    X25519(age::x25519::Recipient),
    Hybrid(age_xwing::HybridRecipient),
}

impl WildcardRecipient {
    pub fn to_string(&self) -> String {
        match self {
            WildcardRecipient::Hybrid(recipient) => recipient.to_string(),
            WildcardRecipient::X25519(recipient) => recipient.to_string(),
        }
    }

    pub fn from_string(key: &String) -> Result<Self> {
        if key.starts_with("age1pq1") {
            Ok(Self::Hybrid(
                age_xwing::HybridRecipient::from_string(key)
                    .map_err(|_| anyhow!("failed to parse key"))?,
            ))
        } else {
            Ok(Self::X25519(
                age::x25519::Recipient::from_str(&key)
                    .map_err(|_| anyhow!("failed to parse key"))?,
            ))
        }
    }
}

impl age::Recipient for WildcardRecipient {
    fn wrap_file_key(
        &self,
        file_key: &age_core::format::FileKey,
    ) -> std::result::Result<
        (
            Vec<age_core::format::Stanza>,
            std::collections::HashSet<String>,
        ),
        age::EncryptError,
    > {
        match self {
            Self::Hybrid(recipient) => recipient.wrap_file_key(file_key),
            Self::X25519(recipient) => recipient.wrap_file_key(file_key),
        }
    }
}

fn to_epoch_secs(time: &SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

impl AppState {
    pub fn generate_fingerprint(key: &String) -> String {
        base32::encode(
            base32::Alphabet::Rfc4648Lower { padding: false },
            key.as_bytes(),
        )
        .split_at(26)
        .0
        .to_string()
    }
    pub fn generate_challenge(&self, public_key: &WildcardRecipient) -> String {
        let fingerprint = AppState::generate_fingerprint(&public_key.to_string());
        let time = to_epoch_secs(&SystemTime::now());
        let mut cipher = ChaCha20Poly1305::new(&self.secret_key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let plaintext = format!("{time}.{fingerprint}");

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();

        BASE64_URL_SAFE_NO_PAD.encode(
            age::encrypt_and_armor(
                public_key,
                BASE64_URL_SAFE_NO_PAD
                    .encode([nonce.as_slice(), ciphertext.as_slice()].concat())
                    .as_bytes(),
            )
            .unwrap(),
        )
    }

    pub fn verify_challenge(&self, challenge: &String) -> Result<String, anyhow::Error> {
        let challenge = BASE64_URL_SAFE_NO_PAD.decode(challenge)?;
        let (nonce, ciphertext) = challenge.split_at(12);

        let mut cipher = ChaCha20Poly1305::new(&self.secret_key.into());
        let plaintext = String::from_utf8(
            cipher
                .decrypt(nonce.try_into()?, ciphertext)
                .map_err(|_| anyhow!("decryption failed"))?,
        )?;

        let (timestamp, fingerprint) = plaintext.split_once(".").unwrap();
        let timestamp = timestamp.parse::<u64>()?;
        let creation_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        if creation_time.elapsed()? > std::time::Duration::from_mins(5) {
            bail!("challenge expired")
        }
        Ok(fingerprint.to_string())
    }
}

#[get("/")]
async fn hello(state: web::Data<AppState>) -> impl Responder {
    let recipient = WildcardRecipient::from_string(&"age1pq1jed327lzn5qtcnjj2x852gpney6m66x3yvhantpmu2egtlq28tu5xgw2fj4fk00dxpmf2rq52s5u2x6ct49kztzcwqxmyquerq9k9gneg7q3suz3z6je8qmfp6e5uh3h5jg98wu6jfpjwvcqfmzvwj4nn36442nntzvfd9mmy3ser05uvwwf5c9tqv86ejpscga5xazpcmxnc4e0dw9zyj9fdm3j3mzzgy3thdtgpvf8hc7y33crm0shk6h2wyajjz6jr3xx9l3ntfzxv7uywt5ewj2t8d2ylvrht7eckf00tykdty8qhce7pkr8fvd59fjdqxs2ddahg9cyz7p9858hfax7nn9xcfyv6pjhhyzq2kx55n0eg87u62gcyswg7tc569dq3pym2k3d9jxexprxky6fc508rsw5fyx6tvruq7j65nurmlav5s9zzdmwfqkq6cdsc4qg47fh9tvp2xxz6vxd0fq4tk9rer7s8wxvhnlan9h6n9524c554pxnymdlvzvyz2he6pax2txggff5eessxel5z7uzv9t38qgrjs6xs3tj8y795xnmza9x5xpvkaru4c7s034cvztsrcncwyuxxtu9rfp5gxtk56t2r255pwwzrhsnk54dsfgdayphpsqc0fvsywghxxk7268x4syvrp46w33gven2pmaf0pfq6uy69d4tw8a2nrryv57fq6w6esfw4g7g4f5uw2a9ecfzw8239q84cumfu2n33g3etz3wjexdpv2r6wj457snzaq3g479gn02nfxq05dxw8jcpnwc26mmhxdmty692pnl8jycwzs25wpw3gpa6gakt2wqtlvh0n2hp2ufytrnyetqmft0qkuuewq530rd2ln9eqprczsgcvsh35xztw5wwezf48yyt3rsukr37mahjjjcw70gdw2ng6mhxksqfy94kdw0h8g6zfk9xw62srjv4aevyr8n03ng02cmdjv2s3ag73tpr5eazpnrhdqnqxgyt8ezrl6cfzpz32d72k6msmzdm3d9ewtxcwcyv5l9j30hrvzjhxwxdkdqxgs0drrhpgtqwcyntrqgf2499r6gnnk35sl0ja6jh79hp77423jjq236awp8a9tddyzmqerv4wefjqrlqyfjxpnl7k6sdx8f2v4aydvgychhekfuxl5kgq7e99mpc69g5v9qcktu6eyj2twy4qv9wp6pfn9padf49h453wu6t6uek99x4ys6msdy7yn9dg7hdeyn2v9wszayz5nf594c8q8tcppszuue0gvmt5r4uysqd3x5q8uh4j7ehyesch98tsw84fh4xrf42e0uqeut99a36l545gmsyche9zpjy72ennyrchky0gunrwjw9suzpqah4wndujcrpr7v9ra2rdls4jqyywp4g4gf7cl5wxqzc0v3ulr5egnvhcur7rq6pk883x6g6qgjh8ynx6wv56vj98uf5r5ugv7znvfdzwenetsv32gmwgk7dfhp5qp3gk3mp6kc5spf5hhqes57u39m9mq8y6yu454a2nqg897c62ylvpcmx9ttsj8yey38pqsgw462qu5yac68xnx7ry4qw9968u36x8djhmrudcaxnsgp2e4th6u5x69nkrtv0u47s6h0488y6vvqp9pxyseygfds2qtkjktt5472gk96rhy6gz4hqz4kwy38n5m02l32l098nc7arsv2jmymscyvk57x5uq6qa8czlrun33ygzgfqwnn5nucc2ddf93jwzj80vucehfx6c8xxuruty8dn2jr8ug474jx3lsxk4qs2vdx4jx267vjjna8e4fy8wpk2lk07xp3hgguw2uw9n2qw5yu8yqvzds3qwf6lks2mjz4qm9kmwrezx92vh843ktwnqqcqtn5k884jarxc3jlzwaf23dqkqs4as6ns3w34kfm8vwcvggz".to_string()).unwrap();
    let thing = state.generate_challenge(&recipient);
    HttpResponse::Ok().body(thing)
}

#[derive(Deserialize)]
struct GetChallengeBody {
    public_key: String,
}

#[post("/challenge")]
async fn get_challenge(
    body: web::Json<GetChallengeBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    let recipient = match WildcardRecipient::from_string(&body.public_key) {
        Ok(recipient) => recipient,
        Err(_) => {
            return HttpResponse::from_error(actix_web::Error::from(
                actix_web::error::ErrorBadRequest("invalid public key"),
            ));
        }
    };
    HttpResponse::Ok().body(state.generate_challenge(&recipient))
}

#[derive(Deserialize)]
struct RegisterRequestBody {
    public_key: String,
    token: String,
    handle: Option<String>,
}

#[post("/register")]
async fn register_key(
    body: web::Json<RegisterRequestBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    if WildcardRecipient::from_string(&body.public_key).is_err() {
        return HttpResponse::BadRequest().body("key is invalid");
    }
    let fingerprint = match state.verify_challenge(&body.token) {
        Ok(fingerprint) => fingerprint,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .body(format!("token is not valid: {}", e.to_string()));
        }
    };

    if AppState::generate_fingerprint(&body.public_key) != fingerprint {
        return HttpResponse::Unauthorized().body("invalid token");
    }

    if body.handle.is_some()
        && state
            .db
            .get_by_handle(&body.handle.clone().unwrap())
            .await
            .is_ok_and(|user| user.is_some())
    {
        return HttpResponse::Conflict().body("handle already in use");
    }

    if state
        .db
        .get_by_id(&fingerprint)
        .await
        .is_ok_and(|user| user.is_some())
    {
        return HttpResponse::Conflict().body("public key already in use");
    }

    let user = User {
        id: fingerprint,
        handle: body.handle.clone(),
        key_content: body.public_key.clone(),
    };
    match state.db.put_user(&user).await {
        Ok(_) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/user/{handle}")]
async fn get_key_from_handle(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let handle = path.into_inner();
    if handle.len() > 20 {
        return HttpResponse::BadRequest().body("invalid handle"); // its too long
    }
    let user = match state.db.get_by_handle(&handle).await {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("failed to query database: {e}"));
        }
    };
    match user {
        Some(user) => HttpResponse::PermanentRedirect()
            .append_header((header::LOCATION, format!("/keys/{}", user.id)))
            .finish(),
        None => return HttpResponse::NotFound().body("failed to find user"),
    }
}

#[get("/keys/{fingerprint}")]
async fn get_key(state: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let fingerprint = path.into_inner();
    if fingerprint.len() != 26 {
        return HttpResponse::BadRequest().body("invalid fingerprint");
    }
    let user = state.db.get_by_id(&fingerprint).await.unwrap();
    if user.is_some() {
        return HttpResponse::Ok().json(user.unwrap());
    } else {
        return HttpResponse::NotFound().body("user not found");
    }
}

#[derive(Deserialize)]
struct UserUpdatePayload {
    handle: Option<String>,
}

#[put("/keys/{fingerprint}")]
async fn update_user(
    body: web::Json<UserUpdatePayload>,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let fingerprint = path.into_inner();
    if fingerprint.len() != 26 {
        return HttpResponse::BadRequest().body("invalid fingerprint");
    }
    let query = state.db.get_by_id(&fingerprint).await;
    let user = match query {
        Ok(user) => user,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };
    let mut user = match user {
        Some(user) => user,
        None => return HttpResponse::NotFound().body("user not found"),
    };
    user.handle = body.handle.clone();
    match state.db.update_user(&fingerprint, user.clone()).await {
        Ok(_) => HttpResponse::Ok().json(user),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn manual_hello() -> impl Responder {
    println!("hi");
    HttpResponse::Ok().body("Hey there!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = dotenvy::dotenv();
    let mut rng = OsRng::default();
    let db = Arc::new(DatabaseClient::new().await.unwrap());
    let mut secret_key = [0u8; 32];
    rng.fill_bytes(&mut secret_key);
    HttpServer::new(move || {
        let db = Arc::clone(&db);
        App::new()
            .app_data(web::Data::new(AppState { secret_key, db }))
            .service(hello)
            .service(update_user)
            .service(get_key)
            .service(get_challenge)
            .service(register_key)
            .service(get_key_from_handle)
            .route("/hey", web::get().to(manual_hello))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
