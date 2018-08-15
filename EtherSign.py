import binascii
import mnemonic
import bip39_struct as bip39
from web3.auto import w3
from eth_account.messages import defunct_hash_message

#To create ethereum recognizable signatures and create signed messages

def recoverSeedFromWords(words):
    seed = mnemonic.Mnemonic().mnemonic_to_seed(mnemonic=words, passphrase='none')
    return seed

def menu():
    ans = True
    while ans:
        print("""
        1.Generate New Mnemonic and Private Key
        2.Sign a Message with Private Key
        3.Recover Private Key with 12 Word Seed
        4.Exit/Quit
        """)
        ans = input("What would you like to do? ")
        if ans == "1":
            word_list = mnemonic.Mnemonic().make_seed()
            sign_data = bip39.bip39_struct(word_list)
            print('Public Key: ', sign_data.priv_key.hex())
            print('Private Key: ', sign_data.priv_key.hex())
            print('12 Word Seed: ', sign_data.word_list)

        elif ans == "2":
            try:
                sign_data
            except NameError:
                print('No Private Key Set. Generate new or recover')
                continue
            print("Input message to be signed")
            message = input()
            message_hash = defunct_hash_message(text=message)
            signed_message = w3.eth.account.signHash(message_hash, private_key= sign_data.priv_key)
            print('hash: ', signed_message.messageHash.hex())
            print('r: ', signed_message.r)
            print('s: ', signed_message.s)
            print('v: ', signed_message.v)


        #elif ans == "3": #todo
           # word_list = input("enter words")
           # menu_priv = Bip39PrivateKey(word_list)
           # print('Public Key: ', menu_priv.pubkey.serialize().hex())
           # print('Private Key: ', menu_priv.serialize())
           # print('12 Word Seed: ', menu_priv.word_list)

        elif ans == "4":
            print("\n Goodbye")

        elif ans != "":
            print("\n Not Valid Choice Try again")


menu()
