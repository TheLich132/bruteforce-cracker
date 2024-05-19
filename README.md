# bruteforce-cracker - a multi-threaded password cracking program written in Rust

## Usage
Generate and save to file the password saved in the /etc/shadow format
> ./brutforce-cracker \<password> \<salt>

Breaking a password using a hash you own
> ./brutforce-cracker \<hashed_password_file> \<passwords_database> \<n_threads>

Benchmark mode. Test from 1 to n CPU cores
> ./brutforce-cracker \<hashed_password_file> \<passwords_database> benchmark \<n_of_passwords_to_test>