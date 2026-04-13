# Enter The Void - Simulación de Micro-Kernel y Exploit en Rust

Este proyecto es una simulación de un kernel de juguete desarrollado en Rust que implementa paginación interna y un shell de usuario basado en IPC. Su objetivo es demostrar conceptos fundamentales de gestión de memoria y vulnerabilidades de seguridad, específicamente simulando una desreferencia de apuntador nulo (Null Pointer Dereference) que permite el escalamiento de privilegios.

**Nota sobre la arquitectura:** El proyecto utiliza un **kernel simulado con paginación interna**. No existe un mapeo literal a la página cero del sistema operativo anfitrión. Todas las operaciones de memoria y exploits ocurren dentro de una arena aislada de 64KB de memoria física simulada.

## Uso

La simulación consta de dos binarios que se comunican mediante Unix Domain Sockets (`/tmp/rust_os_sim.sock`):
1. **Kernel:** El servicio de fondo que gestiona la MMU (Unidad de Manejo de Memoria) y las llamadas al sistema.
2. **User App:** Un shell interactivo que permite al usuario mapear memoria, escribir datos y disparar syscalls.

### Construcción del Proyecto

Se requiere de tener Rust y Cargo instalados, posteriormente se puede compilar con:

```bash
cargo build
```

---

## 1. Ejecución del Kernel

El kernel debe iniciarse primero en su propia terminal. Acepta argumentos de CLI que definen las políticas de seguridad de la simulación.

```bash
cargo run --bin kernel -- [OPCIONES]
```

### Argumentos del Kernel (CLI)

* `--allow-page-zero`
    * **Descripción:** Permite al usuario mapear lógicamente la dirección `0x0`.
    * **Impacto:** Por defecto, los sistemas operativos modernos prohíben mapear la página cero para evitar exploits. Activar esta bandera desactiva esa protección en la simulación.
* `--vulnerable`
    * **Descripción:** Habilita la llamada al sistema `SYS_VULN`.
    * **Impacto:** Esta syscall contiene una falla simulada donde ejecuta o confía ciegamente en el payload ubicado en la memoria física correspondiente a la dirección lógica `0`.

**Ejemplo: Iniciar un kernel inseguro (listo para el exploit)**
```bash
cargo run --bin kernel -- --allow-page-zero --vulnerable
```

---

## 2. Ejecución del shell de usuario

Con el kernel ejecutándose, abrir una **segunda terminal** y ejecutar la aplicación de usuario:

```bash
cargo run --bin user_app
```

Se pedirá un nombre de usuario para el login. Una vez dentro, aparece el prompt `> ` donde se pueden usar los siguientes comandos:

### Comandos disponibles
* `mmap <addr>`: Mapea una página lógica (ej. `mmap 0x0`).
* `write <addr> <val>`: Escribe un byte en una dirección (soporta hex, ej. `write 0 0xCC`).
* `read <addr>`: Lee un byte de la memoria lógica.
* `su`: Intenta escalar privilegios a root de forma convencional (fallará).
* `echo_root <msg>`: Envía un mensaje al log del kernel (solo para usuarios privilegiados).
* `sys_vuln`: Ejecuta la syscall vulnerable.
* `exploit`: Ejecuta la secuencia automatizada de ataque.
* `exit`: Cierra el shell.

---

## 3. Cómo activar el exploit

El objetivo es obtener acceso de root aprovechando la desreferencia del apuntador nulo.

### Requisitos Previos
El kernel **debe** haberse iniciado con las protecciones desactivadas:
```bash
cargo run --bin kernel -- --vulnerable --allow-page-zero
```

### La vulnerabilidad

La syscall `sys_vuln` intenta leer una instrucción desde la dirección lógica `0`, simulando un intento de lectura de un apuntador nulo.
Como el kernel permite mapear dicha página, un usuario puede inyectar un _opcode_ de escalamiento (`0xCC`) en esa dirección y forzar al kernel a ejecutarlo con privilegios elevados.

### Exploit automatizado
En el shell de usuario, simplemente escribe:
```text
> exploit
```

### Explotación manual
Para entender la mecánica, se puede realizar el ataque manualmente:

1. **Verificar que no eres root:**
   ```text
   > echo_root hola
   [KERNEL] ERROR: Unauthorized
   ```
   ```text
   > su
    [KERNEL] ERROR: Unauthorized. (PSW.mode == 0)
   ```
2. **Mapear la dirección lógica 0:**
   ```text
   > mmap 0
   [KERNEL] OK: Mapped successfully
   ```
3. **Inyectar el payload (`0xCC` / `204`):**
   ```text
   > write 0 0xCC
   [KERNEL] OK: Write Successful
   ```
4. **Ejecutar la syscall vulnerable:**
   ```text
   > sys_vuln
   [KERNEL] OK: PRIVILEGE ESCALATION SUCCESSFUL
   ```
5. **Confirmar acceso de root:**
   ```text
   > echo_root Ahora tengo el control
   [KERNEL] OK: Message logged as root
   ```

El mensaje "Ahora tengo el control" se mostrará en la terminal que está ejecutando el kernel, simulando que el usuario ha logrado escribir en un _búfer_ accesible solo a usuarios privilegiados.
