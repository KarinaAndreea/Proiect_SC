# Proiect_SC
Implementarea unui protocol pentru tranzactii online

Step 1: Clientul trimite vanzatorului cheia sa publica criptata.

Step 2: Vanzatorul decripteaza cheia primita de la client si o retine. Este generat un SID, se face semnatura digitala a SID-ului dupa care este trimis un mesaj clientului.

Step 3: Clientul creeaza un mesaj cu informatiile cardului. Acest mesaj este criptat cu cheia publica a PG astefl incat vanzatorul sa nu aiba acces la ele.

Step 4: Vanzatorul trimite informatiile cardului catre PG.

Step 5: PaymentGateway verifica daca informatiile cardului sunt valide si trimite un raspuns vanzatorului.

Step 6: Vanzatorul trimite mesajul primit de la PG catre client.
