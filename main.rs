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
use passwords::{analyzer, scorer}; // password checking
use color_eyre::eyre::{self, Context, Result};  // error handling
use eyre::eyre; // error handling

use std::{
    fs::{File, OpenOptions},
    io::Write,
}; // basic IO
use std::{
    io::Read,
    path::Path,
}; // basic IO

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
        #[clap(value_parser, required = true)]
        files: Vec<String>,

        /// Output file
        #[arg(short, default_value_t = String::from("output.txt"))]
        output: String,
    },
    /// Decrypt a file
    Decrypt {
        #[arg()]
        input: String,

        /// Output folder containing the deciphered files
        #[arg(short, default_value_t = String::from("output_folder"))]
        output: String,
    },
}

const BUFFER_SIZE: usize = 128;
const NONCE_SIZE: usize = 12;
const TAGSIZE: usize = 16;

fn encrypt_file(key_bytes: &[u8], input_file: &mut File, output_file: &mut File) -> Result<()> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);

    // putting the nonce in the ouput
    output_file
        .write(&nonce.as_slice())
        .wrap_err("unable to write nonce")?;

    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        // bytes to read (either a full buffer or there isnt enough bytes to do so)
        let read_count = input_file
            .read(&mut buffer)
            .wrap_err("unable to read file")?;

        let ciphered_data = cipher
            .encrypt(&nonce, &buffer[..read_count])
            .map_err(|e| eyre::eyre!(e))
            .wrap_err("unable to encrypt")?;

        output_file
            .write(&ciphered_data)
            .wrap_err("unable to write into file")?;

        if read_count != BUFFER_SIZE {
            break;
        }
    }
    Ok(())
}

fn decrypt_file(
    key_bytes: &[u8],
    input_file: &mut File,
    output_file: &mut File,
    file_size: u64,
) -> Result<()> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // we need to extract the nonce
    let mut nonce_buff = [0_u8; NONCE_SIZE];

    input_file.read_exact(&mut nonce_buff).unwrap();
    let nonce = Nonce::from_slice(&nonce_buff[..12]);

    let mut size_remaining = file_size as usize; // current file size remaining to be read
                                                 // reading the file using a buffer
    loop {
        // bytes to read (either a full buffer or there isnt enough bytes to do so)
        let mut buffer = vec![0u8; std::cmp::min(size_remaining, BUFFER_SIZE)];
        let read_count = input_file.read(&mut buffer).unwrap();

        let deciphered_data = cipher
            .decrypt(nonce, &buffer[..read_count])
            .map_err(|e| eyre::eyre!(e))
            .wrap_err("failed to decrypt (password probably incorrect)")?;
        output_file.write(&deciphered_data).unwrap();

        size_remaining -= read_count;
        if size_remaining == 0 {
            break;
        }
    }
    Ok(())
}

fn password_score(password: &str) -> f64 {
    scorer::score(&analyzer::analyze(password))
}

// NOTE: La structure d'un fichier chiffré est la suivante: les 4 premiers octets sont pour le nombre de fichiers chiffrés
// les 8 suivants sont la taille du 1 er fichier chiffré, puis 22 octets pour le salt 12 pour le nonce et puis le fichier
// chiffré brut (et ainsi de suite: taille+salt+nonce)
fn main() -> Result<()> {
    color_eyre::install()?;

    // Parse the user input
    let args = Args::parse();

    // prompt for a password
    let password = rpassword::prompt_password("Enter the passphrase: ")
        .wrap_err("Error when reading password")?;

    // check the password strength
    if password_score(&password) < 40.0 { // we could even go as high as 80 (good)
        return Err(eyre!("Password is too weak"));
    }

    match args.mode {
        Mode::Encrypt { files, output } => {
            // open the output file
            let mut output_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&output)
                .wrap_err("unable to create output file")?;

            // we write the number of files that we encrypted in the header
            let number_of_files = files.len() as u32;

            let _ = output_file
                .write_all(&number_of_files.to_le_bytes())
                .wrap_err("unable to write number of files")?;

            // derive a key from the password
            let salt = SaltString::generate(&mut OsRng);
            let hashed = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .unwrap();
            let key = hashed.hash.unwrap();

            // write the salt into the file
            let salt_buffer = salt.as_ref();
            let _ = output_file
                .write_all(salt_buffer.as_bytes())
                .wrap_err("unable to write salt")?;

            // for each file we encrypt and we append it to the file
            for input in files {
                // we open the file
                let mut input_file = OpenOptions::new()
                    .read(true)
                    .open(&input)
                    .wrap_err("unable to open input file")?;

                let file_length = input_file
                    .metadata()
                    .wrap_err("unable to get file metadata")?
                    .len();
                // encrypted file length is calculated using the input file size to wich we add the
                // size of the tag that is put at the end of each chunk (there are file_length/BUFFERSIZE chunks)
                let encrypted_file_length =
                    file_length as usize + ((file_length as usize / BUFFER_SIZE) + 1) * TAGSIZE;

                let _ = output_file
                    .write_all(&encrypted_file_length.to_le_bytes())
                    .wrap_err("unable to write file length")?;

                encrypt_file(key.as_bytes(), &mut input_file, &mut output_file)?;

            }
        }

        Mode::Decrypt { input, output } => {
            let output_path = Path::new(&output);

            // we create an output folder
            let _ = std::fs::create_dir_all(output_path)
                .expect("Error when creating the output folder");

            // we open the input file
            let mut input_file = OpenOptions::new()
                .read(true)
                .open(&input)
                .wrap_err("unable to open input file")?;

            // we get the number of file: the first 4 chars
            let mut number_of_files_buf = [0_u8; 4];

            input_file.read_exact(&mut number_of_files_buf).unwrap();
            let number_of_files = u32::from_le_bytes(number_of_files_buf);

            // we get the salt
            let mut salt_buff = [0_u8; 22];
            let _ = input_file
                .read_exact(&mut salt_buff)
                .wrap_err("unable to read salt")?;
            let salt = SaltString::from_b64(std::str::from_utf8(&mut salt_buff).unwrap()).unwrap();

            // derive a key from the password
            let hashed = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .unwrap();
            let key = hashed.hash.unwrap();

            for i in 0..number_of_files {
                // we get the current file's length
                let mut file_size_buf = [0_u8; 8];

                input_file.read_exact(&mut file_size_buf).unwrap();
                let file_size = u64::from_le_bytes(file_size_buf);

                // we open a new ouput file (file<i>.txt)
                let mut output_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(output_path.join(("file".to_owned()) + &(i.to_string()) + ".txt"))
                    .wrap_err("unable to create output file")?;

                decrypt_file(key.as_bytes(), &mut input_file, &mut output_file, file_size)?;
            }
        }
    }
    Ok(())
}
