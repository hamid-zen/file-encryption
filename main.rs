use clap::{Parser, Subcommand};
use std::fs::{File, OpenOptions};
use std::io::{self};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)] 
enum Mode {
    Encrypt {
        #[arg(short, long)]
        filename: String,
    },
    Decrypt {
        #[arg(short, long)]
        filename: String,
    },
}

fn open_file_rw(filename: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true)   // Lecture autorisée
        .write(true)  // Écriture autorisée
        .create(true) // Crée le fichier s'il n'existe pas
        .open(filename) // Ouvre le fichier ou crée-le
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
        /*Cipher mode*/
        Mode::Encrypt {filename} => {
            // open the file and check if exists
            match open_file_rw(&filename) {
                Ok(_f) => {
                    println!("Fichier '{}' ouvert pour le chiffrement.", filename);
                }
                Err(e) => {
                    println!("Ouverture du fichier {} impossible, erreur : {}", filename, e);
                }
            }
        }

        /*Decrypt mod*/
        Mode::Decrypt {filename} => {
            match open_file_rw(&filename) {
                Ok(_f) => {
                    println!("Fichier '{}' ouvert pour le chiffrement.", filename);
                }
                Err(e) => {
                    println!("Ouverture du fichier {} impossible, erreur : {}", filename, e);
                }

            }
        } 
    }
}
