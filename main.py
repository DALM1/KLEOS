import os
import subprocess

subprocess.run(["clear"], shell=True)
subprocess.run("cd build && ./NetworkMonitoring", shell=True)

print(f"                 __________")
print(f"................~#########%%;~....................")
print(f"............../############%%;`|......@@@.........")
print(f"............./######/~\/~\%%;,;,....@....@........")
print(f"............|#######\    /;;;;.,.|../@@@@.........")
print(f"............|#########\/%;;;;;.,.|................")
print(f" @@XX@......|##/~~\####%;;;/~~\;,|@ .......XX.....")
print(f" XX..X@@@@@@|#|  o  \##%;/  o  |.|@ @@@@@@X..XX...")
print(f"XX.....X@@@@@##\____/##%;\____/.,|@ @@@@@X.....XX.")
print(f" XX.....X@@@@\#########/\;;;;;;,, /@@@@@@X.....XX.")
print(f" @@XX...X@@@@@\######%%//%%%%;,,/@@@@@@@@@X...XX..")
print(f"....@XXX.......\#####//\%%%;.,/............XXX....")
print(f"................\###/____%;,/.......c.............")
print(f".................\##//%%%;/.........||............")
print(f"..................\#|%%;,/........==||m_...........")
print(f"..................\#|%%;,/......//||.|.\...........")
print(f"..................\#|%%;,|\....|||||.|..|.........")
print("\n")
print("                   $CHEMA")
print("\n")

def choix_1():
    print("Exec scrpt 1")

def choix_2():
    print("Exec scrpt 2")

def choix_3():
    print("Exec scrpt 3")

def menu():
    print("Veuillez choisir une option :")
    print("1. Choix 1")
    print("2. Choix 2")
    print("3. Choix 3")
    print("4. Quitter")

    choix = input("Entrez le numéro de votre choix : ")

    if choix == '1':
        choix_1()
    elif choix == '2':
        choix_2()
    elif choix == '3':
        choix_3()
    elif choix == '4':
        print("Bye")
        exit()
    else:
        print("Choix invalide, veuillez réessayer.")
        menu()

if __name__ == "__main__":
    while True:
        menu()
