# CS4783-Project-2
This project demonstrates the additive homomorphic properties of the Paillier cryptosystem by tallying up the results of an election without decrypting any individual vote. Ballots are transmitted via e-mail; they are sent with SMTP and retrieved with IMAP. This means that the transmission of voting data can travel on the existing infrastructure of the public Internet, simplifying greatly the collection of ballots. This system was tested with free e-mail accounts from Microsoft's Outlook.com and Google's Gmail. Only e-mails with the name of the election in the subject line are processed, so existing e-mail accounts can be used.

This repository includes five programs, each of which is explained below.

## admin-keygen
Run this program to input the number of candidates and the maximum number of voters. The program will also ask you to name the election and to specify an e-mail address to which encrypted votes should be sent. A public/private key pair is generated and saved to the disk as `public-key.txt` and `private-key.txt`. The public key file also contains the number of candidates, the maximum number of voters, the name of the election, and the e-mail address.

## admin-tokens
Run this program to generate some random tokens. This program guarantees that all of the generated tokens are unique. Tokens are saved to a file on the disk called `tokens.txt`. You can open this text file in a text editor to see the tokens and send them to voters. Note that this program does not check that the number of tokens generated is less than the maximum number of voters specified to `admin-keygen`.

## cast-vote
Once `admin-keygen` and `admin-tokens` have been run, distribute the following to each voter:
* A copy of `cast-vote`
* `public-key.txt`, which should be placed in the current working directory
* One token from `tokens.txt`
The user should configure `ssmtp` on the system first and then run this program to cast a vote. The program will prompt for the voter token and prompt the user to pick a candidate. The ballot will be encrypted and written to `email.txt`, after which the user can run `ssmtp [e-mail address] <email.txt` to send the vote. The e-mail address that was provided to `admin-keygen` will be displayed to the user. A message authentication code is also included in the e-mail.

## imap-get-votes.py
This is the only script that is written in Python. This script connects to the IMAP server, fetches e-mails with the name of the election in the subject line, and puts the encrypted votes in `votes-downloaded.txt`.

## tally-votes
This program is responsible to verifying the message authentication codes and tallying up the votes. If two votes are submitted with the same voter token, then only the first is counted. At the end, this program prints out the number of votes for each candidate. It reads encrypted votes and message authentication codes from stdin, so just run `tally-votes <votes-downloaded.txt` to see the results of the election. This program does not save any data when it is run; you can run it whenever `votes-downloaded.txt` is updated.
