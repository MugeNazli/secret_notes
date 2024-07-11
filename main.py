import tkinter
from tkinter import *
import base64
from tkinter import messagebox


window = tkinter.Tk()
window.minsize(width=500,height=700)
window.title("SECRET NOTES")
window.config(pady=10,padx=10)






def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

#save notes
def save_and_encrypt():
    title = my_entry.get()
    message = my_text.get("1.0",END)
    master_secret = my_entry2.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted = encode(master_secret, message)

        try:
            with open("secret_notes.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("secret_notes.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            my_entry.delete(0, END)
            my_entry2.delete(0, END)
            my_text.delete("1.0",END)

def decrypt():
    message_encrypted = my_text.get("1.0", END)
    master_secret = my_entry2.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            my_text.delete("1.0", END)
            my_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")



photo = PhotoImage(file="Untitled design (2)-min (1).png")
photo_label = Label(image=photo)
photo_label.pack()


my_label = tkinter.Label(text="enter your title")
my_label.config(fg="black",font=("Arial",15,"italic"))
my_label.pack()
my_label.config(padx=20,pady=20)
my_entry = tkinter.Entry(width=40)
my_entry.insert(string="entry title...",index=0)
my_entry.pack()
my_entry.focus()

my_label = tkinter.Label(text="enter your secret")
my_label.config(fg="black",font=("Arial",15,"italic"))
my_label.pack()
my_label.config(padx=20,pady=20)



my_text = tkinter.Text(width=40,height=20)
my_text.pack()



my_label = tkinter.Label(text="enter master key")
my_label.config(fg="black",font=("Arial",15,"italic"))
my_label.pack()
my_label.config(padx=20,pady=20)

my_entry2 = tkinter.Entry(width=40)
my_entry2.insert(string="entry password...",index=0)
my_entry2.pack()




my_button = tkinter.Button(width=25,text="save & encrypt",command=save_and_encrypt)
my_button.pack()


my_button = tkinter.Button(width=12,text="decrypt",command=decrypt)
my_button.pack()



window.mainloop()