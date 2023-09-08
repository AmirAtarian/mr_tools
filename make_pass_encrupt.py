import random
import string


class Password:
    """
    create random password with number,letter and symbols.
    """
    letter = string.ascii_letters
    number = "0123456789"
    symbols = '~!@#$%^&*()_+=-|":}{['
    all_join = letter + number + symbols

    def __init__(self, length: int = 4) -> None:
        self.length = length
        self.pass_1 = "".join(random.sample(self.all_join, self.length))

    def make_pass(self) -> str:
        return self.pass_1

    def save_pass(self) -> None:
        a = open("pass_save", "a+")
        a.write(f"{self.pass_1}\n")
        a.close()


class Encrypt:
    def __init__(self, text: str) -> None:
        self.text = text

    def encrypt(self) -> None:
        encrypt = []
        for i in self.text:
            s = 0
            x = ord(i[s]) * 4 + 3
            encrypt.append(chr(x))
            s = +1

        encrypt_text = "".join(encrypt)
        print(f"encrypted text:{encrypt_text}\n")

    def decrypt(self):
        decrypt = []

        for i in self.text:
            s = 0
            x = int((ord(i[s]) - 3) / 4)
            decrypt.append(chr(x))
            s = +1

        decrypt_text = "".join(decrypt)
        print(f"decrypted text:{decrypt_text}\n")


def main():
    while True:
        print("choose one option:\n\t1.make password\n\t2.encrypt text\n\t3.decrypt text\n\t4.exit")
        num = input()
        if num == "1":
            text = int(input("type the length of password:"))
            passa = Password(text)
            print("your password:", passa.make_pass())
            save_pass = input("do you want to save it in a file?(yes/no)")
            if save_pass == "yes":
                passa.save_pass()
            else:
                print("ok!!")
                continue
        elif num == "2":
            text_2 = input("type the text that you want to encrypt:")
            t = Encrypt(text_2)
            t.encrypt()
        elif num == "3":
            text_3 = input("type the text that you want to decrypt:")
            t = Encrypt(text_3)
            t.decrypt()
        elif num == "4":
            print("see you soon!!!")
            break


if __name__ == "__main__":
    main()
