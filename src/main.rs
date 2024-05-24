use memmap2::Mmap;
use password_encryptor::{EncryptionData, PasswordEncryptor};
use rayon::prelude::*;
use std::fs::File;
use std::io::{stdout, Write};
use std::sync::{Mutex, MutexGuard};
use std::{env, fs, process::exit, time};

const KEY: &[u8] = b"secret key";

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 3 {
        hash_password(&args[1], &args[2]);
    } else if args.len() == 4 && args[3] != "benchmark" {
        crack_password(&args[1], &args[2], args[3].parse().unwrap_or(1));
    } else if args.len() == 5 && args[3] == "benchmark" {
        benchamrk(&args[1], &args[2], args[4].parse().unwrap_or(2500));
    } else {
        println!("Usage:\n{} <password> <salt>\nor\n{} <hashed_password_file> <passwords_database> <n_threads>\nor\n{} <hashed_password_file> <passwords_database> benchmark <n_of_passwords_to_test>\n", args[0], args[0], args[0]);
        exit(1);
    }
}

pub fn hash_password(password: &str, salt: &str) {
    let prefix: String = format!("$6${}$", salt);
    let encryptor: PasswordEncryptor = PasswordEncryptor::new(KEY, Some(prefix.as_str()));
    let data: EncryptionData = EncryptionData {
        content: password,
        salt,
    };

    let hashed_password: String = encryptor
        .encrypt_password(&data)
        .unwrap_or(String::from(""));

    println!("{}\n", hashed_password);

    // save password to file "password"
    fs::write("./password", hashed_password).expect("Unable to write file");
    exit(0);
}

fn crack_password(hashed_password_file: &str, passwords_database: &str, mut n_threads: i32) {
    // load hashed password from file
    let hashed_password: String = fs::read_to_string(hashed_password_file).expect("Unable to read file");

    // break password to used algorithm, salt and hash
    let mut password_parts: Vec<&str> = hashed_password.split('$').collect::<Vec<&str>>();
    password_parts.remove(0);
    if password_parts.len() != 3 {
        println!("Invalid hashed password file");
        exit(1);
    }
    println!(
        "Used algorithm: {}\nSalt: {}\nHash: {}\n",
        password_parts[0], password_parts[1], password_parts[2]
    );

    if n_threads < 0 || n_threads > num_cpus::get() as i32 {
        println!(
            "Invalid number of threads. Using {} threads.",
            num_cpus::get()
        );
        n_threads = num_cpus::get() as i32;
    }

    rayon::ThreadPoolBuilder::new()
        .num_threads(n_threads as usize)
        .build_global()
        .unwrap();

    let passwords: File = File::open(passwords_database).unwrap();
    let map: Mmap = unsafe { Mmap::map(&passwords).unwrap() };
    let map: Vec<&[u8]> = map.split(|&c| c == b'\n').collect::<Vec<&[u8]>>();
    let passwords_len: usize = map.len() - 1;

    let prefix: String = format!("${}${}$", password_parts[0], password_parts[1]);

    let i: i32 = 0;
    let mutex_i: Mutex<i32> = Mutex::new(i);

    map.par_iter().for_each(|&password| {
        if let Ok(password_) = std::str::from_utf8(password) {
            let encryptor: PasswordEncryptor = PasswordEncryptor::new(KEY, Some(prefix.as_str()));
            let data: EncryptionData = EncryptionData {
                content: password_,
                salt: password_parts[1],
            };
            let test_password: String = encryptor
                .encrypt_password(&data)
                .unwrap_or(String::from(""));

            let mut guard: MutexGuard<i32> = mutex_i.lock().unwrap();
            *guard += 1;

            if *guard % 100 == 0 {
                print!("\r{} / {}", *guard, passwords_len);
                //flush line
                stdout().flush().unwrap();
            }

            if test_password == hashed_password {
                println!("\n\nPassword found: {}", password_);
                exit(0);
            }
        }
    });

    println!("Password not found");
    exit(0)
}

fn benchamrk(hashed_password_file: &str, passwords_database: &str, mut n: i32) {
    // load hashed password from file
    let hashed_password: String =
        fs::read_to_string(hashed_password_file).expect("Unable to read file");

    // break password to used algorithm, salt and hash
    let mut password_parts: Vec<&str> = hashed_password.split('$').collect::<Vec<&str>>();
    password_parts.remove(0);
    if password_parts.len() != 3 {
        println!("Invalid hashed password file");
        exit(1);
    }
    // println!(
    //     "Used algorithm: {}\nSalt: {}\nHash: {}\n",
    //     password_parts[0], password_parts[1], password_parts[2]
    // );

    let passwords: File = File::open(passwords_database).unwrap();
    let map: Mmap = unsafe { Mmap::map(&passwords).unwrap() };
    let map: Vec<&[u8]> = map.split(|&c| c == b'\n').collect::<Vec<&[u8]>>();

    if n < 0 {
        n = map.len() as i32 - 1;
    }

    let max_threads: i32 = num_cpus::get() as i32;

    let prefix: String = format!("${}${}$", password_parts[0], password_parts[1]);
    println!("Testing on {} passwords...\n", n);

    for n_threads in 1..=max_threads {
        println!("Testing {} threads...", n_threads);
        let pool: rayon::ThreadPool = rayon::ThreadPoolBuilder::new()
            .num_threads(n_threads as usize)
            .build()
            .expect("Unable to build thread pool");

        let start: time::Instant = time::Instant::now();

        let i: i32 = 0;
        let mutex_i: Mutex<i32> = Mutex::new(i);

        pool.install(|| {
            let _ = map.par_iter().try_for_each(|&password| {
                if let Ok(password_) = std::str::from_utf8(password) {
                    let encryptor: PasswordEncryptor = PasswordEncryptor::new(KEY, Some(prefix.as_str()));
                    let data: EncryptionData = EncryptionData {
                        content: password_,
                        salt: password_parts[1],
                    };
                    let _ = encryptor
                        .encrypt_password(&data)
                        .unwrap_or(String::from(""));

                    let mut guard: MutexGuard<i32> = mutex_i.lock().unwrap();
                    *guard += 1;

                    if *guard % 20 == 0 {
                        print!("\r{} / {}", *guard, n);
                        //flush line
                        stdout().flush().unwrap();
                    }
                    
                    if *guard >= n {
                        return Err(());
                    }
                }
                Ok(())
            });
        });
        let end: time::Instant = time::Instant::now();

        println!("\n{} threads: {} s\n", n_threads, (end - start).as_secs_f64());
    }
}
