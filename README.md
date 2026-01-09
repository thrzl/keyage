# keyage

an age keyserver that collects as little information as possible

this service only stores the following information from you:
- your public key content
  - a fingerprint (`base32(public_key)[:26]`)
- a username (optional)

this makes it so that keys can be obtained via a fingerprint or username vs having to directly pass the full key text. it was originally intended for use with the MLKEM768-X25519 recipient type, as the public keys are over 1k characters long which makes them terrible to share

## how this works

authentication works like this:
1. the user sends their public key 
2. the server generates a token encrypted to the user.
3. the user decrypts the token with their private key.
4. the token is verified when a request is made.

tokens are roughly:
```py
fingerprint = Base32.lower(public_key)[:26]
timestamp = SystemTime.now().as_secs()
plaintext = timestamp || "." || fingerprint

# for chacha20poly1305:
# - the secret key is a random 32-byte app secret generated when the service is started
# - the nonce is also just a random 12 bytes  
token = base64_url_safe.encode(chacha20poly1305(plaintext))
```

because chacha20poly1305 is an AEAD, tokens aren't traceable to any given user and the data is verified as legitimate when it's decrypted by the server.

additionally, to avoid blind token usage, you must send the public key content (maybe i'll change it to fingerprint?) alongside the token.

lastly, having the user decrypt the token with their public key ensures that they are the actual owner of the key being authenticated.

## under the hood

the most important crates used are:

- actix-web - web framework
- libsql - client for the libsql sqlite fork (built by/for turso)
- age - implementation of the age encryption format
- age-xwing - implementation of the MLKEM768-X25519 recipient type
