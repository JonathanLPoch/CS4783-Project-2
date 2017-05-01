# CS4783 Project 2
This project demonstrates the additive homomorphic properties of the Paillier cryptosystem by tallying up the results of an election without decrypting any individual vote. Ballots are transmitted via e-mail; they are sent with SMTP and retrieved with IMAP. This means that the transmission of voting data can travel on the existing infrastructure of the public Internet, simplifying greatly the collection of ballots. This system was tested with free e-mail accounts from Microsoft's Outlook.com and Google's Gmail. Only e-mails with the name of the election in the subject line are processed, so existing e-mail accounts can be used.

To build programs in this repository, you will need to install the following libraries:
* [GNU Multiple Precision](https://gmplib.org/)
* [Paillier Library](http://hms.isi.jhu.edu/acsc/libpaillier/)
* [Crypto++](http://packages.ubuntu.com/trusty/libcrypto++-dev) --- On Ubuntu 14.04 LTS, you can run `sudo apt-get install libcrypto++-dev` to install Crypto++.

## The programs
This repository includes five programs, each of which is explained below.

### admin-keygen
Run this program to input the number of candidates and the maximum number of voters. The program will also ask you to name the election and to specify an e-mail address to which encrypted votes should be sent. A public/private key pair is generated and saved to the disk as `public-key.txt` and `private-key.txt`. The public key file also contains the number of candidates, the maximum number of voters, the name of the election, and the e-mail address.

It is a good idea to specify a maximum number of voters greater than the actual number of voters. In the event that a voter ID token is compromised, a new one can be issued.

You will not be asked to name the candidates; you need to assign each of the candidates a number starting from 1. Please inform your voters of which number is which candidate.

### admin-tokens
Run this program to generate the random voter ID tokens. This program guarantees that all of the generated tokens are unique. Tokens are saved to a file on the disk called `tokens.txt`. You can open this text file in a text editor to see the tokens and send them to voters.

### cast-vote
Once `admin-keygen` and `admin-tokens` have been run, distribute the following to each voter:
* A copy of `cast-vote`
* `public-key.txt`, which should be placed in the current working directory
* One token from `tokens.txt`

The user should configure `ssmtp` on the system first and then run this program to cast a vote. The program will prompt for the voter token and prompt the user to pick a candidate. The ballot will be encrypted and written to `email.txt`, after which the user can run `ssmtp [e-mail address] <email.txt` to send the vote. The e-mail address that was provided to `admin-keygen` will be displayed to the user. A message authentication code is also included in the e-mail.

### imap-get-votes.py
This is the only script that is written in Python. This script connects to the IMAP server, fetches e-mails with the name of the election in the subject line, and puts the encrypted votes in `votes-downloaded.txt`.

### tally-votes
This program is responsible to verifying the message authentication codes and tallying up the votes. If two votes are submitted with the same voter token, then only the first is counted. At the end, this program prints out the number of votes for each candidate. It reads encrypted votes and message authentication codes from stdin, so just run `tally-votes <votes-downloaded.txt` to see the results of the election. This program does not save any data when it is run; you can run it whenever `votes-downloaded.txt` is updated.

## Election integrity and confidentiality
In a high-stakes election, users are highly motivated to change the results. Even authorized voters who have genuine voter ID tokens may try to vote more than once or vote for more than one candidate. Here are a few attacks that users may try:

### Unauthorized voting
The election administrator uses `admin-keygen` and `admin-tokens` to generate a public/private key pair and a unique token for each voter. The token should be kept secure. When a vote with an unauthorized token is submitted, `tally-votes` prints a message and does not count the vote.

### Seeing other people's votes
The secrecy of the ballot is key to a fair election because it makes retaliation impractical. `cast-vote` encrypts votes with a 2048-bit public key. The Paillier encryption algorithm adds a random value before encrypting, so two votes for the same candidate do not have the same ciphertext.

When the vote is transmitted over e-mail, it is encrypted, and users can add an additional layer of protection by configuring `ssmtp` to use an SMTP server that supports STARTTLS. Once the vote arrives on the computer of the election administrator, however, it still does not need to be decrypted. Because of the additive homomorphic properties of the Paillier cryptosystem, `tally-votes` can tell you how many votes each candidate got without decrypting any individual vote.

### Modifying other people's votes
After encrypting a vote, `cast-vote` generates a SHA-256 checksum of the encrypted vote. This checksum is concatenated with the voter ID token, and the result is encrypted and sent with the encrypted vote. If a vote has been modified, the SHA-256 checksum will fail to verify; in this event, `tally-votes` prints a message and does not count the vote. The election administrator may issue a new token and contact the voter to resubmit.

### Submitting a valid vote more than once
People sometimes accidentally send e-mails twice, but that's okay. When two votes are submitted with the same token, `tally-votes` prints a message and only counts the first vote.

### Submitting a ballot with more than one vote
Mathematically, it is possible to send a single ballot with one of the following irregularities:
* At least one candidate has more than one vote
* More than one candidate has a vote
* Both of the above

There is a simple way to check for this, though: the total number of votes for all candidates should equal the number of ballots received. This check is performed by `tally-votes` at the very end. If the two numbers do not match, the election results cannot be trusted.

In addition, `cast-vote` actually includes a reverse ballot. If `tally-votes` processes the reverse ballot like it does the regular ballot, then the result is the same as the regular result, except that the candidates are reversed. For example, suppose that, from the regular ballots, candidate A gets 5 votes, candidate B gets 4 votes, candidate C gets 3 votes, and candidate D gets 2 votes; from the reverse ballots, candidate A gets 2 votes, candidate B gets 3 votes, candidate C gets 4 votes, and candidate D gets 5 votes. If the results from the reverse ballots are reversed again, they should match the results from the regular ballots. If they do not match, the election results cannot be trusted.

### Specifying additional candidates
Although a user-specified candidate could not possibly be interpreted correctly because it is not a candidate that you specified, it should not be allowed. To detect this, `tally-votes` performs a quick check for unknown candidates and prints a warning if it finds any.
