use clap::{Arg, Command};
use elf::ElfFile;

mod elf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("readelf-rs")
        .version("1.0")
        .author("Gustavo Noronha Silva <gustavo@noronha.dev.br>")
        .about("A simple implementation of readelf in Rust")
        .arg(
            Arg::new("elf")
                .help("Path to the ELF file")
                .required(true)
                .index(1),
        )
        .get_matches();

    let path = matches.get_one::<String>("elf").unwrap();

    let elf_file = ElfFile::new(path)?;

    println!("Successfully memory-mapped ELF file: {}", path);

    println!("{}", elf_file);

    Ok(())
}
