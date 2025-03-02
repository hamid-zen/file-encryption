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
use std::{io::{self, Read}, path::Path};
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

fn open_file_rw(filename: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true) // lecture
        .write(true) // ecriture
        .create(true) // le creer si il existe pas
        .open(filename)
}

const BUFFER_SIZE: usize = 128;
const NONCE_SIZE: usize = 12;
const TAGSIZE: usize = 16;

fn encrypt_file(key_bytes: &[u8], input_file: &mut File, output_file: &mut File) -> () {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);

    // putting the nonce in the ouput
    output_file.write(&nonce.as_slice()).unwrap();
    
    // reading the file using a buffer
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        // bytes to read (either a full buffer or there isnt enough bytes to do so)
        let read_count = input_file.read(&mut buffer).unwrap();

        let ciphered_data = cipher
            .encrypt(&nonce, &buffer[..read_count])
            .expect("failed to encrypt");
        output_file.write(&ciphered_data).unwrap();

        if read_count != BUFFER_SIZE {
            break;
        }
    }
}

fn decrypt_file(key_bytes: &[u8], input_file: &mut File, output_file: &mut File, file_size: u64) -> () {
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

        let deciphered_data = cipher.decrypt(nonce, &buffer[..read_count]);
        match deciphered_data {
            Ok(deciphered_chunk) => {
                output_file.write(&deciphered_chunk).unwrap();
            }
            Err(_) => {
                return;
            }
        }

        if read_count != std::cmp::min(size_remaining, BUFFER_SIZE) {
            break;
        }
        size_remaining -= read_count;
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
            let mut _output_file: Result<File, io::Error> =
                OpenOptions::new().write(true).create(true).open(&output);

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

                    // write the salt into the file
                    let salt_buffer = salt.as_ref();
                    let _ = output
                        .write_all(salt_buffer.as_bytes())
                        .expect("error when writing salt");

                    // for each file we encrypt and we append it to the file
                    for input in files.unwrap() {
                        // we open the file
                        match open_file_rw(&input) {
                            Ok(mut input_file) => {

                                let file_length = input_file
                                    .metadata()
                                    .expect("error when getting file metadata")
                                    .len();
                                // encrypted file length is calculated using the input file size to wich we add the 
                                // size of the tag that is put at the end of each chunk (there are file_length/BUFFERSIZE chunks)
                                let encrypted_file_length = file_length as usize+((file_length as usize/BUFFER_SIZE)+1)*TAGSIZE;

                                let _ = output
                                    .write_all(&encrypted_file_length.to_le_bytes())
                                    .expect("error when writing metadata to file");
                                encrypt_file(key.as_bytes(), &mut input_file, &mut output);
                            }
                            Err(e) => {
                            }
                        }
                    }
                }
                Err(e) => {
                }
            }
        }

        Mode::Decrypt { input, output } => {

            let output_path = Path::new(&output);

            // we create an output folder
            let _ = std::fs::create_dir_all(output_path).expect("Error when creating the output folder");

            // we open the input file
            let mut _input_file: Result<File, io::Error> =
                OpenOptions::new().read(true).open(&input);

            match _input_file {
                Ok(mut input_file) => {
                    // we get the number of file: the first 4 chars
                    let mut number_of_files_buf = [0_u8; 4];
                    input_file.read_exact(&mut number_of_files_buf).unwrap();
                    let number_of_files = u32::from_le_bytes(number_of_files_buf);

                    // we get the salt
                    let mut salt_buff = [0_u8; 22];
                    let _ = input_file
                        .read_exact(&mut salt_buff)
                        .expect("error when reading salt");
                    let salt =
                        SaltString::from_b64(std::str::from_utf8(&mut salt_buff).unwrap()).unwrap();

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
                            .read(true)
                            .write(true)
                            .create(true)
                            .open(output_path.join(("file".to_owned())+&(i.to_string())+".txt"))
                            .expect("error when creating output file");

                        decrypt_file(key.as_bytes(), &mut input_file, &mut output_file, file_size);
                    }
                }
                Err(e) => {
                }
            }
        }
    }
}
