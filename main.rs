use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
}; // cipher
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
}; // derivation
use clap::{Parser, Subcommand}; // arg parsing
use rpassword; // password prompting
use std::io::{self, Read};
use std::{
    fs::{File, OpenOptions},
    io::{Seek, Write},
};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version="1.0", about="Simple program to encrypt/decrypt a file. Made by @ZizouChrist and @ResistantCorse", long_about=None)]
struct Args {
    #[command(subcommand)]
    mode: Mode,

    #[arg(short, default_value_t = String::from("output.txt"))]
    output: String,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Encrypt a file
    Encrypt {
        #[arg()]
        filename: String,
    },
    /// Decrypt a file
    Decrypt {
        #[arg()]
        filename: String,
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
            .expect("failed to encrypt"); // TODO: gerer ça

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
    let mut nonce_buff = [0_u8; 12]; // TODO replacer la taille par un const
    input_file.read_exact(&mut nonce_buff).unwrap(); // TODO voir pourquoi ? ne marche pas + peut etre utiliser read et verifier la taille lue
    let nonce = Nonce::from_slice(&nonce_buff[..12]);

    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let read_count = input_file.read(&mut buffer).unwrap();

        let deciphered_data = cipher.decrypt(nonce, &buffer[..read_count])
            .expect("failed to encrypt"); // TODO: gerer ça

        output_file.write(&deciphered_data).unwrap();

        if read_count != BUFFER_SIZE {
            break;
        }
    }
}

fn decrypt(key_bytes: &[u8], encrypted_data: Vec<u8>) -> String {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);

    let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_arr);

    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphered_data)
        .expect("failed to decrypt data"); //TODO gerer ça

    String::from_utf8(plaintext).expect("failed to convert vector of bytes to string")
    //TODO gerer ça
}

/*Comment gérer le mdp : */
// On a un mdp qu'on doit gérer de façon sécuriser à la fois à l'input
// et durant le lifetime de la variable de mdp, il faut la laisser
// la moins longtemps possible en vie.
// On en calcule une clé dérivée qui est le hash(mdp)
// On utilise un chiffrement symértrique avec pour clé le hash du mdp

fn main() {
    // Parse the user input
    let args = Args::parse();
    // open input file

    match args.mode {
        Mode::Encrypt { filename } => {
            // on ouvre le fichier
            match open_file_rw(&filename) {
                Ok(_file) => {
                    println!("Fichier '{}' ouvert pour le chiffrement.", filename);

                    let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();

                    // derive a key from the password
                    let salt = SaltString::generate(&mut OsRng);
                    let hashed = Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .unwrap();
                    let key = hashed.hash.unwrap();

                    // testing encryption
                    let mut input_file = OpenOptions::new()
                        .read(true)
                        .open("test_file.txt")
                        .unwrap();
                    let mut encrypt_output = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open("encrypt_output.txt")
                        .unwrap();
                    encrypt_file(key.as_bytes(), &mut input_file, &mut encrypt_output);

                    // testing decryption
                    encrypt_output.rewind().unwrap();
                    let mut decrypt_output = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open("decrypt_output.txt")
                        .unwrap();
                    decrypt_file(key.as_bytes(), &mut encrypt_output, &mut decrypt_output);
                    // let decrypted = decrypt(key.as_bytes(), encrypted);
                    // println!("decrypted: {:?}", decrypted);
                }
                Err(e) => {
                    println!(
                        "Ouverture du fichier {} impossible, erreur : {}",
                        filename, e
                    );
                }
            }
        }

        Mode::Decrypt { filename } => match open_file_rw(&filename) {
            Ok(_file) => {
                println!("Fichier '{}' ouvert pour le chiffrement.", filename);

                let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();
            }
            Err(e) => {
                println!(
                    "Ouverture du fichier {} impossible, erreur : {}",
                    filename, e
                );
            }
        },
    }
}
