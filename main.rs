use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
}; // cipher
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
}; // derivation
use clap::{Parser, Subcommand}; // arg parsing
use rpassword; use core::str;
// password prompting
use std::io::{self, Read};
use std::{
    fs::{File, OpenOptions},
    io::Write,
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version="1.0", about="Simple program to encrypt/decrypt a file. Made by @ZizouChrist and @ResistantCorse", long_about=None)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Encrypt a file
    Encrypt {
        #[arg()]
        input: String,

        #[arg(short, default_value_t = String::from("output.txt"))]
        output: String,
    },
    /// Decrypt a file
    Decrypt {
        #[arg()]
        input: String,

        #[arg(short, default_value_t = String::from("output.txt"))]
        output: String,
    },
}

fn open_file_rw(filename: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true) // lecture
        .write(true) // ecriture
        .create(true) // le creer si il existe pas
        .open(filename)
}

const BUFFER_SIZE: usize = 128;
const NONCE_SIZE: usize = 12;

fn encrypt_file(key_bytes: &[u8], input_file: &mut File, output_file: &mut File) -> () {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);

    // putting the nonce in the ouput
    output_file.write(&nonce.as_slice()).unwrap();

    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let read_count = input_file.read(&mut buffer).unwrap();

        let ciphered_data = cipher
            .encrypt(&nonce, &buffer[..read_count])
            .expect("Failed to encrypt");

        output_file.write(&ciphered_data).unwrap();

        if read_count != BUFFER_SIZE {
            break;
        }
    }
}

fn decrypt_file(key_bytes: &[u8], input_file: &mut File, output_file: &mut File) -> () {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // we need to extract the nonce
    let mut nonce_buff = [0_u8; NONCE_SIZE];
    input_file.read_exact(&mut nonce_buff).unwrap();
    let nonce = Nonce::from_slice(&nonce_buff[..12]);

    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let read_count = input_file.read(&mut buffer).unwrap();

        let deciphered_data = cipher
            .decrypt(nonce, &buffer[..read_count])
            .expect("Wrong password");

        output_file.write(&deciphered_data).unwrap();

        if read_count != BUFFER_SIZE {
            break;
        }
    }
}

//NOTE: On a eu un choix a faire dans ce projet: On a utilisé un chiffrement par chunks oû on stocke le salt et le nonce dans le "header" du fichier chiffré ce qui fait qu'on ne peut pas utiliser le meme fichier a chiffrer pour l'output
// Une autre façon de le faire est de charger tout le fichier d'input dans la memoire et d'ainsi pouvoir overwrite le fichier
fn main() {
    // Parse the user input
    let args = Args::parse();

    match args.mode {
        Mode::Encrypt { input, output } => {
            // on ouvre le fichier
            match open_file_rw(&input) {
                Ok(mut input_file) => {

                    let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();

                    // derive a key from the password
                    let salt = SaltString::generate(&mut OsRng);
                    let hashed = Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .unwrap();
                    let key = hashed.hash.unwrap();

                    let _output_file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&output);

                    match _output_file {
                        Ok(mut output_file) => {

                            // we add the salt
                            let _ = output_file.write(salt.as_str().as_bytes());
                            encrypt_file(key.as_bytes(), &mut input_file, &mut output_file);
                        }
                        Err(e) => {
                            println!(
                                "Ouverture du fichier {} impossible, erreur : {}",
                                output, e
                            );
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "Ouverture du fichier {} impossible, erreur : {}",
                        input, e
                    );
                }
            }
        }

        Mode::Decrypt { input, output } =>
            // on ouvre le fichier
            match open_file_rw(&input) {
                Ok(mut input_file) => {

                    let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();

                    // Note: an encrypted file is structured like this: the 22 first bytes are the salt, 
                    // then we have the rest of the file (raw file)
                    // we get the salt from the input file
                    let mut salt_buff = [0_u8; 22];
                    let _ = input_file.read_exact(&mut salt_buff).expect("error when reading salt");
                    let salt = SaltString::from_b64(std::str::from_utf8(&mut salt_buff).unwrap()).unwrap();
                    
                    // derive a key from the password
                    let hashed = Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .unwrap();
                    let key = hashed.hash.unwrap();

                    let _output_file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&output);

                    match _output_file {
                        Ok(mut output_file) => {
                            decrypt_file(key.as_bytes(), &mut input_file, &mut output_file);
                        }
                        Err(e) => {
                            println!(
                                "Ouverture du fichier {} impossible, erreur : {}",
                                output, e
                            );
                        }
                    }
                },
                Err(e) => {
                    println!(
                        "Ouverture du fichier {} impossible, erreur : {}",
                        input, e
                    );
                }
            }
    }
}
