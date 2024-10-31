# SHA256-Password-Cracking
## Disclaimer
_This script is provided for educational purposes only._

_The unauthorized use of this tool to crack passwords or access systems without permission is illegal and unethical._

_- Always ensure you have explicit authorization before attempting to test or breach any system's security._

_- The author and distributor of this script are not responsible for any misuse or damage caused by its application._

<br>

## Screenshots:
<img width="902" alt="sha256-crack" src="https://github.com/user-attachments/assets/6315bb84-eff6-4d9c-82c1-8c125ccead69">

<img width="328" alt="2024-10-31 20_10_09-kali-linux-2024 3 - VMware Workstation" src="https://github.com/user-attachments/assets/c2606ed3-4f59-485d-913a-0f33c644abaa">

<br>
<br>

## Steps to perform Password Cracking of a SHA256 hash using the provided script:

#### Step 1: Make sure pwntools is installed in your Kali Linux Virtual Machine.
    sudo apt-get install python3-pwntools 
<br>

#### Step 2: Make use of your own wordlist.
<br>

#### Step 3: Obtain the Hash(SHA-256) of a given word from the wordlist:
    echo -ne "any word from the wordlist" | sha256sum
<br>

#### Step 4: Use the SHA256 Hash obtained in the previous step to find the corresponding plain text password:
    python3 sha256-crack.py "Provide the SHA256 Hashed Password"
<br>

## Detailed overview of how to write the script:

#### 1. Import required libraries:
    from pwn import *
    import sys
<br>

#### 2. Check for correct command-line arguments:
    if len(sys.argv) != 2:            
        print("Invalid arguments!")
        print(">> {} <sha256sum>".format(sys.argv[0]))
        exit()
<br>

#### 3. Set up variables:
    wanted_hash = sys.argv[1]
    password_file = "/usr/share/wordlists/rockyou.txt"
    attempts = 0
<br>

#### 4. Create a progress bar using pwntools:
    with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
<br>

#### 5. Open the password file and iterate through each password:
    with open(password_file, "r", encoding='latin-1') as password_list:
            for password in password_list:
<br>

#### 6. Process each password and compare hashes:
    password = password.strip("\n").encode('latin-1')
                password_hash = sha256sumhex(password)
                p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
<br>

#### 7. Check if the hash matches and exit if found:
    if password_hash == wanted_hash:
                    p.success("Password has found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'), password_hash))
                    exit()
                attempts += 1
<br>

#### 8. If the password is not found, display a failure message:
    p.failure("Password hash not found!")

<br>
