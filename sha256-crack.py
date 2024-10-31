from pwn import *
import sys

if len(sys.argv) != 2:                #Get arguments from the command line
	       
	print("Invalid arguments!")
	print(">> {} <sha256sum>".format(sys.argv[0]))
	exit()
	
wanted_hash = sys.argv[1]
print(wanted_hash)

password_file = "/usr/share/wordlists/rockyou.txt"         #Assign a password file
attempts = 0

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
	with open(password_file, "r", encoding='latin-1') as password_list:
		for password in password_list:
			password = password.strip("\n").encode('latin-1')
			password_hash = sha256sumhex(password)                  #sha256sumhex is a function obtained from the Pwn Module
			
			p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
			if password_hash == wanted_hash:
				p.success("Password hash found after {} attempts!. The password {}, hashes to {}!".format(attempts, password.decode('latin-1'), password_hash)) 				
				exit()
			attempts += 1
		p.failure("Password Hash not found!")