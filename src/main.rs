mod database;

use actix_web::{App, HttpResponse, HttpServer, Responder, Result, get, http::header, post, web};
use anyhow::{anyhow, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, KeyInit,
    aead::{AeadMut, OsRng, rand_core::RngCore},
};
use database::DatabaseClient;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{str::FromStr, sync::Arc};

use crate::database::User;

struct AppState {
    secret_key: [u8; 32],
    db: Arc<DatabaseClient>,
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
    pub fn generate_challenge(&self, public_key: &String) -> String {
        let fingerprint = AppState::generate_fingerprint(public_key);
        let time = to_epoch_secs(&SystemTime::now());
        let mut cipher = ChaCha20Poly1305::new(&self.secret_key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let plaintext = format!("{time}.{fingerprint}");

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();

        BASE64_URL_SAFE_NO_PAD.encode(
            age::encrypt_and_armor(
                &age::x25519::Recipient::from_str(public_key.as_str()).unwrap(),
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
    let thing = state.generate_challenge(
        &"age1rrep76nztgx5y59d2gf3fyuc45k2jkqcsn7ae6zjfpfkuayggy2q5h0j86".to_string(),
    );
    HttpResponse::Ok().body(thing)
}

#[derive(serde::Deserialize)]
struct GetChallengeBody {
    public_key: String,
}

#[post("/challenge")]
async fn get_challenge(
    body: web::Json<GetChallengeBody>,
    state: web::Data<AppState>,
) -> impl Responder {
    if age::x25519::Recipient::from_str(&body.public_key).is_err() {
        return HttpResponse::from_error(actix_web::Error::from(
            actix_web::error::ErrorBadRequest("invalid public key"),
        ));
    }
    HttpResponse::Ok().body(state.generate_challenge(&body.public_key))
}

#[derive(serde::Deserialize)]
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

    let user = User {
        id: fingerprint,
        handle: body.handle.clone(),
        key_content: body.public_key.clone(),
    };
    if state.db.put_user(&user).await.is_err() {
        return HttpResponse::InternalServerError().body("failed to register user");
    };
    HttpResponse::Ok().json(user)
}

#[get("/user/{handle}")]
async fn get_key_from_handle(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let handle = path.into_inner();
    if handle.len() > 20 {
        return HttpResponse::BadRequest().body("invalid username"); // its too long
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
        return HttpResponse::NotFound().body("failed to find user");
    }
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
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
            .service(echo)
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
