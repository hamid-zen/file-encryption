use clap::{Parser, Subcommand}; // arg parsing
use rpassword; // password prompting
use argon2::{
    password_hash::{SaltString, rand_core::OsRng},
    Argon2, Params, PasswordHasher,
}; // derivation
use hex::ToHex; // debug purposes
use std::fs::{File, OpenOptions};
use std::io::{self};

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
        .read(true)   // lecture
        .write(true)  // ecriture
        .create(true) // le creer si il existe pas 
        .open(filename)
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
        Mode::Encrypt {filename} => {
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

                    let data = hashed.hash.unwrap();

                    assert_eq!(data.len(), 32);

                    println!("{}", data.encode_hex::<String>());
                }
                Err(e) => {
                    println!("Ouverture du fichier {} impossible, erreur : {}", filename, e);
                }
            }
        }

        Mode::Decrypt {filename} => {
            match open_file_rw(&filename) {
                Ok(_file) => {
                    println!("Fichier '{}' ouvert pour le chiffrement.", filename);

                    let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();

                }
                Err(e) => {
                    println!("Ouverture du fichier {} impossible, erreur : {}", filename, e);
                }

            }
        } 
    }
}
