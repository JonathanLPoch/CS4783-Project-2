#!/usr/bin/env python3
import email, getpass, imaplib, subprocess, sys
OUTPUT_FILENAME = "votes-downloaded.txt"

print("This script will download encrypted votes from an IMAP mailbox.")
if len(sys.argv) == 4:
    # Establish a connection to the IMAP server.
    M = imaplib.IMAP4_SSL(host=sys.argv[1])
    # Prompt the user for IMAP credentials.
    M.login(sys.argv[2], getpass.getpass("Enter IMAP password: "))
    print()
    try:
        # Navigate into the inbox.
        M.select()
        # Open a file to save the votes in.
        with open(OUTPUT_FILENAME, "w") as votes_downloaded:
            # Search for and download votes.
            typ, data = M.search(None, "SUBJECT", "\"Vote: " + sys.argv[3] + "\"")
            for num in data[0].split():
                # Fetch the message.
                typ, data = M.fetch(num, '(RFC822)')
                # Decode the message.
                message = email.message_from_bytes(data[0][1])
                sender = message.get("From", "unknown party")
                # Write the vote to the file.
                print("Saving vote from ", sender, "...", sep="")
                votes_downloaded.write("Vote from ")
                votes_downloaded.write(sender)
                votes_downloaded.write("\n")
                votes_downloaded.write(message.get_payload(decode=True).replace(b"\r\n", b"\n").replace(b"\r", b"\n").decode("UTF-8"))
                votes_downloaded.write("\n")
    finally:
        M.close()
        M.logout()
    print("\nThe e-mail bodies have been saved to a file:", OUTPUT_FILENAME)
    print("Run `./tally-votes <", OUTPUT_FILENAME, "` to tally the votes.", sep="")
else:
    print("Usage: imap-tally.py [IMAP server] [IMAP username] [name of election]")
    print("The IMAP server should support SSL on port 993.")
    print("The name of the election should not contain quotation marks or exclamation points.")
