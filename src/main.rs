#![allow(dead_code)]
#![feature(iter_intersperse)]
#[macro_use]
extern crate lazy_static;
extern crate clap;

use crate::prime_check::{decrypt, encrypt, PrimeUtils};
use clap::{Parser, Subcommand};
use convert::{base64_to_key, key_to_base64};
use std::io::Read;

mod convert;
mod prime_check;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Gen,
    Encrypt { message: Option<String> },
    Decrypt { secret: Option<String> },
}

fn main() -> std::io::Result<()> {
    let end_char = if cfg!(target_os = "windows") {
        'Z'
    } else {
        'D'
    };
    let mut checker = PrimeUtils::new(1024);
    let cli = Cli::parse();
    match cli.command {
        Commands::Gen => {
            let (pub_key, pri_key) = checker.gen_key();
            std::fs::write("id_rsa.pub", key_to_base64(&pub_key).as_bytes())?;
            std::fs::write("id_rsa", key_to_base64(&pri_key).as_bytes())?;
            println!("id_rsa.pub & id_rsa have been generated.");
        }
        Commands::Encrypt { message } => {
            let message = message.unwrap_or_else(|| {
                println!("Please input the message. Ctrl + {} to end.", end_char);
                let mut content = String::new();
                std::io::stdin().read_to_string(&mut content).unwrap();
                content
            });
            let public_key =
                base64_to_key(&String::from_utf8(std::fs::read("id_rsa.pub").unwrap()).unwrap());
            println!("{}", encrypt(&public_key, &message))
        }
        Commands::Decrypt { secret } => {
            let secret = secret.unwrap_or_else(|| {
                println!("Please input the secret. Ctrl + {} to end.", end_char);
                let mut content = String::new();
                std::io::stdin().read_to_string(&mut content).unwrap();
                content
            });
            let private_key =
                base64_to_key(&String::from_utf8(std::fs::read("id_rsa").unwrap()).unwrap());
            print!("\n{}", decrypt(&private_key, &secret))
        }
    }
    Ok(())
}
