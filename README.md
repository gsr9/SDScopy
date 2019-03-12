# SDS
Conocimiento cero

1. Registro
  * Antes de enviar hash
  * Servidor almacena hash
  * Encriptar el registro del login con clave del servidor (salsa20?)
2. Login
  * Enviar passwd hasheado
  * Respuesta ok y token
3. Añadir passwords del usuario
  * Usr |passwd |url
  * Cliente1.json
  * Añadir o Recuperar
  * Trabajamos con el fichero, el cliente cifra y descifra con su clave
  * Si cambiamos contraseña recuperar y volver a cifrar el fichero
  * Generar random pass cifrada con la clave del cliente
4. Listar mis contraseñas


## Servidor
* Registrarse (Guardar usuario y contraseña en el archivo login) (¿validación, email?)
* Autenticarse (comprobar que existen las credenciales en el fichero login y devolver token)
* Devolver el fichero al cliente
* Recibir el fichero del cliente y almacenarlo en el lugar correspondiente
* En caso de trabajar con ficheros almacenar y recuperar de la carpeta asociada al cliente

## Cliente
* Cifrar contraseña (salsa 20?) (hashear?)
* Enviar la contraseña hasheada al servidor para autenticarnos/registrarnos
* Ver si existe el fichero, sino crear uno nuevo
* ¿Al añadir una nueva entrada al fichero de contraseñas, ciframos la pass?
* Cifrar/Descifrar el fichero con las entradas (salsa20)
* Listar entradas del fichero
* Eliminar una entrada en concreto
* Enviar el fichero cifrado al servidor (token válido)
## Extras
*	Programar una extensión ([Get started](https://developer.chrome.com/extensions/getstarted)) de Google Chrome que se comunique con el servidor para buscar contraseñas guardadas y se puedan usar fácilmente en el navegador.
*	Generación de contraseñas aleatorias y por perfiles (longitud, grupos de caracteres, pronunciabilidad, etc.)
*	Añadir datos adicionales
*	Compartir contraseña con grupos de usuarios usando clave pública


