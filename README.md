# Practica Final PSP - SSL Simulada

## Compilar (Java 9+)

La generacio del certificat utilitza `sun.security.x509`, per tant cal exposar el modul:

```bash
javac --add-exports java.base/sun.security.x509=ALL-UNNAMED -d out $(find src -name "*.java")
```

## Executar

Terminal 1 (servidor):

```bash
java --add-exports java.base/sun.security.x509=ALL-UNNAMED -cp out practica.u5.Server
```

Terminal 2 (client):

```bash
java --add-exports java.base/sun.security.x509=ALL-UNNAMED -cp out practica.u5.Client
```

Per simular un certificat fals (ha de fallar la validacio):

```bash
java --add-exports java.base/sun.security.x509=ALL-UNNAMED -cp out practica.u5.Client --tamper-cert
```

## Flux implementat

1. El client demana el certificat al servidor.
2. El servidor genera un parell de claus RSA i un certificat autofirmat i envia el certificat.
3. El client valida el certificat i extreu la clau publica.
4. El client genera una clau simetrica AES i envia la clau + hash xifrats amb RSA.
5. El servidor valida el hash, guarda la clau simetrica i rep paraules xifrades amb AES.
6. El servidor valida hash, imprimeix la paraula i envia l'ACK "DataRecived" xifrat.
