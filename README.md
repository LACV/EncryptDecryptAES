EncryptDecryptAES


AddRoundKey
Este procedimiento realiza una operación XOR entre el estado y una clave de ronda en un algoritmo de cifrado, aumentando la seguridad del proceso.

AESDecrypt
En 14 rondas, este procedimiento revierte la encriptación AES. Comienza deshaciendo las operaciones realizadas durante la encriptación, incluyendo desplazamientos, sustituciones y mezclas de columnas.

AESEncrypt
Este procedimiento encripta datos en 14 rondas, aplicando sustituciones, desplazamientos y mezclas de columnas en cada iteración. Es la parte central de la encriptación AES.

AESExpandKey
Se encarga de expandir la clave de cifrado AES en un conjunto de subclaves para su uso en las rondas de cifrado. Garantiza que la clave esté lista para su aplicación en cada ronda.

BytesToHex
Esta función toma un array de bytes y lo convierte en una representación hexadecimal, útil para convertir datos binarios en una forma legible.

DecryptPassword
Utilizando AES y una clave específica, este procedimiento desencripta una contraseña previamente cifrada, devolviéndola en su formato original.

EncryptPassword
Este procedimiento toma una contraseña en texto claro y la encripta mediante AES, devolviendo el resultado en formato hexadecimal, lo que es común en aplicaciones de seguridad.

HexToBytes
Convierte una cadena hexadecimal en un array de bytes. Útil para revertir la operación de BytesToHex, recuperando datos binarios a partir de una representación hexadecimal.

InvMixColumns
Este procedimiento deshace la transformación "MixColumns" en AES. Revirtiendo la mezcla de columnas en el estado, restaura la disposición original de los datos.

InvShiftRows
En el algoritmo AES, este procedimiento realiza el desplazamiento inverso de las filas en el estado, lo que es necesario para deshacer el proceso de encriptación.

InvSubBytes
Realiza la sustitución inversa de bytes en el estado utilizando la tabla InvSbox del algoritmo AES, deshaciendo la sustitución original.

MixColumns
Este procedimiento ejecuta la operación de mezcla de columnas en el estado del cifrado AES. Multiplica cada columna por una matriz específica para asegurar la confidencialidad de los datos.

Mult
Multiplica bytes en GF(256) usando tablas LogTable e InvLogTable en AES. Esta operación es fundamental para las transformaciones en AES.

RCon
Genera valores Rcon para expandir claves AES utilizando multiplicación en GF(256). Estos valores son críticos para garantizar la seguridad en las rondas de cifrado.

RotWord
Rota una palabra de 32 bits (Cardinal) 8 bits hacia la izquierda. Esta operación es necesaria para las transformaciones en AES.

ShiftRows
Realiza el desplazamiento de filas en una matriz de estado en el contexto del algoritmo de cifrado AES. Este procedimiento es clave para el proceso de encriptación.

StringToAESKey
Convierte una cadena de texto en una clave AES, asegurando que la clave tenga una longitud de 32 bytes. Esto es necesario para aplicar la encriptación de manera efectiva.

SubBytes
Realiza la sustitución de bytes en el estado utilizando la tabla Sbox en el algoritmo AES. Esta operación es parte integral del proceso de encriptación.

SubWord
Sustituye una palabra de 32 bits con Sbox de AES y retorna el resultado. Esta operación es esencial para la seguridad en AES.