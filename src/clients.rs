use std::{io::Error, path::PathBuf};

use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};

use serde::Deserialize;
use tokio::fs;

#[derive(Deserialize, Debug, Clone)]
pub struct Client {
    pub key: String,
    pub hash: String,
}

pub async fn read_clients_file(clients_config: &PathBuf) -> Result<Vec<Client>, Error> {
    let contents = fs::read_to_string(clients_config).await?;
    let clients: Vec<Client> = serde_json::from_str(&contents.as_str())?;

    Ok(clients)
}

pub fn client_login_is_valid(
    key: &String,
    password: &String,
    clients: &Vec<Client>,
) -> Result<bool, ()> {
    let mut client_iter = clients.iter();

    if let Some(client) = client_iter.find(|client| &client.key == key) {
        if let Ok(parsed_hash) = PasswordHash::new(&client.hash) {
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok())
        } else {
            Err(())
        }
    } else {
        Ok(false)
    }
}

/*
    #######################################################################################
    ######################################## TESTS ########################################
    #######################################################################################
*/

#[cfg(test)]
mod tests {
    use super::{client_login_is_valid, Client};

    #[test]
    fn test_hash_validation_correct() {
        let clients = vec![
            Client {
                key: String::from("foo"),
                hash: String::from(
                    "$argon2id$v=19$m=32,t=2,p=1$V3hudnFvVEJwTnFjNGRMVA$E+sVHTGn3oMAFHhk27r05A",
                ),
            },
            Client {
                key: String::from("iyoshok"),
                hash: String::from(
                    "$argon2id$v=19$m=16,t=2,p=1$bGVWbjBzNEFxZTZLSkh2MA$Z1pgP1acelPKkL2nny9XsA",
                ),
            },
        ];

        let test_res = client_login_is_valid(&String::from("foo"), &String::from("bar"), &clients);
        assert!(test_res.is_ok());
        assert!(test_res.unwrap());
    }

    #[test]
    fn test_hash_validation_incorrect() {
        let clients = vec![
            Client {
                key: String::from("foo"),
                hash: String::from(
                    "$argon2id$v=19$m=32,t=2,p=1$V3hudnFvVEJwTnFjNGRMVA$E+sVHTGn3oMAFHhk27r05A",
                ),
            },
            Client {
                key: String::from("iyoshok"),
                hash: String::from(
                    "$argon2id$v=19$m=16,t=2,p=1$bGVWbjBzNEFxZTZLSkh2MA$Z1pgP1acelPKkL2nny9XsA",
                ),
            },
        ];

        let test_res = client_login_is_valid(&String::from("foo"), &String::from("barr"), &clients);
        assert!(test_res.is_ok());
        assert!(!test_res.unwrap());

        let test_res = client_login_is_valid(&String::from("fooo"), &String::from("bar"), &clients);
        assert!(test_res.is_ok());
        assert!(!test_res.unwrap());
    }
}
