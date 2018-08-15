from web3.auto import w3
import mnemonic

class bip39_struct:
    def __init__(self, word_list):
        self.priv_key =  mnemonic.Mnemonic.mnemonic_to_seed(word_list, passphrase='none')
        self.pub_key = w3.eth.account.privateKeyToAccount(self.priv_key)
        self.word_list = word_list