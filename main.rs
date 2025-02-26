use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
}; // cipher
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
}; // derivation
use clap::{Parser, Subcommand}; // arg parsing
use core::str;
use rpassword;
// password prompting
use std::io::{self, Read};
use std::{
    fs::{File, OpenOptions},
    io::Write,
};

#[derive(Parser, Debug)]
#[command(version="1.0", about="Simple program to encrypt/decrypt a file. Made by @ZizouChrist and @ResistantCorse", long_about=None)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

//NOTE: On a eu un choix a faire dans ce projet: On a utilisé un chiffrement par chunks oû on stocke le salt et le nonce dans le "header" du fichier chiffré ce qui fait qu'on ne peut pas utiliser le meme fichier a chiffrer pour l'output
// Une autre façon de le faire est de charger tout le fichier d'input dans la memoire et d'ainsi pouvoir overwrite le fichier
#[derive(Subcommand, Debug)]
enum Mode {
    /// Encrypt a file
    Encrypt {
        #[clap(value_parser)]
        files: Option<Vec<String>>,

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
    let mut nonce_buff = [0_u8; NONCE_SIZE];
    input_file.read_exact(&mut nonce_buff).unwrap(); // TODO voir pourquoi ? ne marche pas + peut etre utiliser read et verifier la taille lue
    let nonce = Nonce::from_slice(&nonce_buff[..12]);

    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let read_count = input_file.read(&mut buffer).unwrap();

        let deciphered_data = cipher.decrypt(nonce, &buffer[..read_count]);
        match deciphered_data {
            Ok(deciphered_chunk) => {
                output_file.write(&deciphered_chunk).unwrap();
            }
            Err(_) => {
                println!("Passphrase incorrect ! ");
                return;
            }
        }
        if read_count != BUFFER_SIZE {
            break;
        }
    }
}

/*Comment gérer le mdp : */
// On a un mdp qu'on doit gérer de façon sécuriser à la fois à l'input
// et durant le lifetime de la variable de mdp, il faut la laisser
// la moins longtemps possible en vie.
// On en calcule une clé dérivée qui est le hash(mdp)
// On utilise un chiffrement symértrique avec pour clé le hash du mdp

// NOTE: La structure d'un fichier chiffré est la suivante: les 4 premiers octets sont pour le nombre de fichiers chiffrés
// les 8 suivants sont la taille du 1 er fichier chiffré, puis 22 octets pour le salt 12 pour le nonce et puis le fichier 
// chiffré brut (et ainsi de suite: taille+salt+nonce)
fn main() {
    // Parse the user input
    let args = Args::parse();

    // prompt for a password
    let password = rpassword::prompt_password("Enter the passphrase: ").unwrap();

    match args.mode {
        Mode::Encrypt { files, output } => {
            // open the output file
            let mut _output_file: Result<File, io::Error> = OpenOptions::new().write(true).create(true).open(&output);

            match _output_file {
                Ok(mut output) => {

                    // we write the number of files that we encrypted in the header
                    let number_of_files = files.as_ref().unwrap().len() as u32;
                    let _ = output
                        .write_all(&number_of_files.to_le_bytes())
                        .expect("error when writing metadata");

                    // derive a key from the password
                    let salt = SaltString::generate(&mut OsRng);
                    let hashed = Argon2::default()
                        .hash_password(password.as_bytes(), &salt)
                        .unwrap();
                    let key = hashed.hash.unwrap();

                    // for each file we encrypt and we append it to the file
                    for input in files.unwrap() {
                        // we open the file
                        match open_file_rw(&input) {
                            Ok(mut input_file) => {
                                let file_length = input_file.metadata().expect("error when getting file metadata").len();
                                let _ = output.write_all(&file_length.to_le_bytes()).expect("error when writing metadata to file");

                                let _ = output.write(salt.as_str().as_bytes()); // we add the salt
                                encrypt_file(key.as_bytes(), &mut input_file, &mut output);
                            }
                            Err(e) => {
                                println!("Impossible to open file: {}, error : {}", input, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Impossible to open file: {}, error : {}", output, e);
                }
            }
        }

        Mode::Decrypt { input, output } =>
        {
            // we open the input file to determine the number of files to decrypt
            let mut _input: Result<File, io::Error> = OpenOptions::new().read(true).open(&input);

            match _input {
                Ok(mut input_file) => {
                    let mut num_files_bytes = [0u8; 4];
                    input_file.read_exact(&mut num_files_bytes).expect("error when reading number of files");
                    let num_files = u32::from_le_bytes(num_files_bytes);
                    println!("number of files encrypted: {}", num_files);
                }
                Err(_e) => {

                }
            }
        }
    }
}
