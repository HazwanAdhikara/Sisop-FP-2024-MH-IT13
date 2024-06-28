# Sisop-FP-2024-MH-IT13

**KELOMPOK IT13**
| Nama | NRP |
|---------------------------|------------|
|Muhamad Arrayyan | 5027231014 |
|Hazwan Adhikara Nasution | 5027231017 |
|Muhammad Andrean Rizq Prasetio | 5027231052 |

## Pengantar

Laporan resmi ini dibuat terkait dengan Final Project Sistem Operasi yang telah dilaksanakan pada tanggal 8 Juni 2024 hingga tanggal 22 Juni 2024. Final Project terdiri dari 1 soal yang saling berkorelasi dan dikerjakan oleh kelompok praktikan yang terdiri dari 3 orang selama waktu tertentu.

Kelompok IT13 melakukan pengerjaan Final Project ini dengan pembagian sebagai berikut:

- Setiap orang mengerjakan dengan sistem saling melanjutkan dengan fitur git command

Sehingga dengan demikian, Pembagian bobot pengerjaan soal menjadi (Rayyan 33.3%, Hazwan 33.3%, Andre 33.3%).

Kelompok IT13 juga telah menyelesaikan Final Project Sistem Operasi yang telah diberikan dan telah melakukan demonstrasi kepada Asisten lab. Dari hasil Final Project yang telah dilakukan sebelumnya, maka diperoleh hasil sebagaimana yang dituliskan pada setiap bab di bawah ini.

## Ketentuan

Struktur Repository Seperti Berikut:

```bash
-fp/
---discorit.c 
---monitor.c 
---server.c 

```

---

## **`DiscorIT`**

### > Isi Soal

### Membuat DiscorIT
#### Disclaimer
- Program server, discorit, dan monitor TIDAK DIPERBOLEHKAN menggunakan perintah `system();`
- 
#### Bagaimana Program Diakses
- Untuk mengakses DiscorIT, user perlu membuka program client (discorit). discorit hanya bekerja sebagai client yang mengirimkan request user kepada server.
Program server berjalan sebagai server yang menerima semua request dari client dan mengembalikan response kepada client sesuai ketentuan pada soal. Program server berjalan sebagai daemon. 
- Untuk hanya menampilkan chat, user perlu membuka program client (monitor). Lebih lengkapnya pada poin monitor.
- Program client dan server berinteraksi melalui socket.
- Server dapat terhubung dengan lebih dari satu client.

#### Tree
DiscorIT/
- channels.csv
- users.csv
- channel1/
  - admin/
    - auth.csv
      - user.log
  - room1/
    - chat.csv
  - room2/
    - chat.csv
  - room3/
    - chat.csv
- channel2/
  - admin/
    - auth.csv
    - user.log
  - room1/
    - chat.csv
  - room2/
    - chat.csv
  - room3/
    - chat.csv

### Keterangan setiap file
  
`DiscorIT`
| File | Isi | Keterangan |
| :---:| :--- | :---      |
| `users.csv` | id_user |  int (mulai dari 1) |
|      | name | string |
|      | password |  string (di encrypt menggunakan bcrypt biar ga tembus) |
|      | global_role | string (pilihannya: ROOT / USER) |
| `channels.csv` | id_channel | int  (mulai dari 1) |
|      | channel | string |
|      | key |  string (di encrypt menggunakan bcrypt biar ga tembus) |

`Channels`
| File | Isi | Keterangan |
| :---:| :--- | :---      |
| `auth.csv` | id_user | int |
|      | name | string |
|      | role | string (pilihannya: ROOT/ADMIN/USER/BANNED) |
| `user.log` | [dd/mm/yyyy HH:MM:SS] | admin buat room1 |
|      | [dd/mm/yyyy HH:MM:SS] | user1 masuk ke channel “say hi” |
|      | [dd/mm/yyyy HH:MM:SS] | admin memberi role1 kepada user1 |
|      | [dd/mm/yyyy HH:MM:SS] | admin ban user1 |

`Rooms`
| File | Isi | Keterangan |
| :---:| :--- | :---      |
| `chat.csv` | date | int |
|      | id_chat | number  (mulai dari 1) |
|      | sender | string |
|      | chat | string |

**Autentikasi**
- Setiap user harus memiliki username dan password untuk mengakses DiscorIT. Username, password, dan global role disimpan dalam file 'user.csv'.
- Jika tidak ada user lain dalam sistem, user pertama yang mendaftar otomatis mendapatkan role "ROOT". Username harus bersifat unique dan password wajib di encrypt menggunakan menggunakan bcrypt.

#### > Penyelesaian



#### > Penjelasan

<details>

<summary>Code</summary>

### Register

You can add text within a collapsed section. 

You can add an image or a code block, too.

```c
   void registerUser(int server_socket, char *username, char *password)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, password);
    sendCommand(server_socket, buffer);

    if (receiveResponse(server_socket, buffer, sizeof(buffer)))
    {
        printf("%s\n", buffer); // Print server response
    }
}
```
</details>

<details>

<summary>Code</summary>

### Login
```c
void loginUser(int server_socket, char *username, char *password)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "LOGIN %s %s", username, password);
    sendCommand(server_socket, buffer);

    if (receiveResponse(server_socket, buffer, sizeof(buffer)))
    {
        if (strstr(buffer, "berhasil login") != NULL)
        {
            printf("%s\n", buffer); // Print server response
            printf("[%s] ", username);
            while (1)
            {
                if (fgets(buffer, sizeof(buffer), stdin) != NULL)
                {
                    buffer[strcspn(buffer, "\n")] = 0;
                    if (strncmp(buffer, "JOIN ", 5) == 0)
                    {
                        char channel[BUFFER_SIZE];
                        sscanf(buffer + 5, "%s", channel);
                        joinChannel(server_socket, username, channel);
                    }
                    else if (strcmp(buffer, "EXIT") == 0)
                    {
                        break;
                    }
                    else if (strcmp(buffer, "JOIN CHANNEL") == 0)
                    {
                        handleCommand(server_socket, buffer);
                        sendCommand(server_socket, buffer);
                    }
                    else if (strcmp(buffer, "LIST CHANNEL") == 0)
                    {
                        handleCommand(server_socket, buffer);
                    }
                    else if (strcmp(buffer, "LIST ROOM") == 0)
                    {
                        handleCommand(server_socket, buffer);
                    }
                    else if (strcmp(buffer, "LIST USER") == 0)
                    {
                        handleCommand(server_socket, buffer);
                    }
                    else
                    {
                        printf("Unknown command\n");
                    }
                }
                printf("[%s] ", username); // Prompt again after command
            }
        }
        else
        {
            printf("%s\n", buffer); // Print server response
            exit(EXIT_FAILURE);
        }
    }
}
```

</details>

#### > Dokumentasi

#### > Revisi
