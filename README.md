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
Pada final project ini, praktikan diminta untuk membuat sebuah aplikasi tiruan Discord dengan konsep-konsep yang sudah di pelajari di modul-modul sebelumnya.

### Membuat DiscorIT
#### Disclaimer
- Program server, discorit, dan monitor TIDAK DIPERBOLEHKAN menggunakan perintah `system();`
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

----

#### > Penyelesaian
### Server.c
<details>

<summary>Code server.c</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8082
#define BUFFER_SIZE 1024

#define MAX_FILENAME_LEN 100
#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define MAX_CHANNELS 10
#define MAX_ROOMS 10
#define MAX_USERS 100
#define SALT_LEN 16

typedef struct
{
    int socket;
    struct sockaddr_in address;
} client_t;

void handleClient(client_t *client);
void *clientHandler(void *arg);
int user_exists(const char *username);
char *get_user_role(const char *username);
void registerUser(char *username, char *password, int client_socket);
void hashPassword(const char *password, char *hashed_password);
void loginUser(char *username, char *password, int client_socket);
void listChannels(int client_socket);
void listRooms(int client_socket);
void listUser(int client_socket);
void joinChannel(char *username, char *channel, int client_socket);
void joinRoom(char *username, char *channel, char *room, int client_socket);
void chatMessages(char *username, char *channel, char *room, char *message, int client_socket);
void seeChat(char *username, char *channel, char *room, int client_socket);
void editChat(char *username, char *channel, char *room, int id, char *new_message, int client_socket);
void deleteChat(char *username, char *channel, char *room, int id, int client_socket);
void errorResponse(char *message, int client_socket);
void sigint_handler(int sig);
void createChannel(char *channel, char *key, int client_socket, char *user);
int findUser(char *username);
void editChannel(char *old_name, char *new_name, int client_socket);
void deleteChannel(char *channel_name, int client_socket);

int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    pthread_t tid;

    signal(SIGINT, sigint_handler);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while (1)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0)
        {
            perror("Accept failed");
            continue;
        }

        client_t *client = malloc(sizeof(client_t));
        client->socket = client_socket;
        client->address = client_addr;

        if (pthread_create(&tid, NULL, clientHandler, (void *)client) != 0)
        {
            perror("Thread creation failed");
            close(client_socket);
            free(client);
        }
    }

    close(server_socket);
    return 0;
}

void *clientHandler(void *arg)
{
    client_t *client = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(client->socket, buffer, BUFFER_SIZE - 1)) > 0)
    {
        buffer[bytes_read] = '\0';

        char *entity = strtok(NULL, " ");
        char *command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0)
        {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            registerUser(username, password, client->socket);
        }
        else if (strcmp(command, "LOGIN") == 0)
        {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            loginUser(username, password, client->socket);
        }
        else if (strcmp(command, "JOIN") == 0)
        {
            char *username = strtok(NULL, " ");
            char *channel = strtok(NULL, " ");

            if (strcmp(entity, "CHANNEL") == 0)
            {
                joinChannel(username, channel, client->socket);
            }
            else if (username == NULL || channel == NULL)
            {
                errorResponse("Invalid JOIN command format", client->socket);
            }
            else
            {
                printf("Handling JOIN for user: %s to channel: %s\n", username, channel); // Log
            }
        }

        else if (strcmp(command, "LIST") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                listChannels(client->socket);
            }
            else if (strcmp(entity, "ROOM") == 0)
            {
                listRooms(client->socket);
            }
            else if (strcmp(entity, "USER") == 0)
            {
                listUser(client->socket);
            }
        }
        else if (strcmp(command, "CREATE") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *channel = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                char *username = strtok(NULL, " ");
                createChannel(channel, key, client->socket, username);
            }
        }
        else if (strcmp(command, "EDIT") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *old_name = strtok(NULL, " ");
                char *new_name = strtok(NULL, " ");
                editChannel(old_name, new_name, client->socket);
            }
        }
        else if (strcmp(command, "DEL") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *channel_name = strtok(NULL, " ");
                deleteChannel(channel_name, client->socket);
            }
        }
        else
        {
            errorResponse("Invalid command", client->socket);
        }
    }

    free(client);
    close(client->socket);
    return NULL;
}

int user_exists(const char *username)
{
    FILE *fp = fopen("DiscorIT/users.csv", "r");
    if (fp == NULL)
    {
        perror("Failed to open users.csv");
        return 0;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp))
    {
        char *token = strtok(line, ",");
        if (token != NULL && strcmp(token, username) == 0)
        {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

char *get_user_role(const char *username)
{
    static char role[10];
    FILE *fp = fopen("DiscorIT/users.csv", "r");
    if (fp == NULL)
    {
        perror("Failed to open users.csv");
        return NULL;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp))
    {
        char *file_username = strtok(line, ",");
        char *file_role = strtok(NULL, "\n");

        if (strcmp(file_username, username) == 0)
        {
            strcpy(role, file_role);
            fclose(fp);
            return role;
        }
    }
    fclose(fp);
    return NULL;
}

void registerUser(char *username, char *password, int client_socket)
{
    char response[BUFFER_SIZE];

    if (user_exists(username))
    {
        snprintf(response, sizeof(response), "%s sudah terdaftar", username);
    }
    else
    {
        FILE *fp = fopen("DiscorIT/users.csv", "a+");
        if (fp == NULL)
        {
            perror("Failed to open users.csv");
            snprintf(response, sizeof(response), "Gagal membuka file users.csv");
        }
        else
        {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            const char *role = (file_size == 0) ? "ROOT" : "USER";

            // Hash the password
            char hashed_password[65]; // 64 characters + null terminator
            hashPassword(password, hashed_password);

            // Append new user to users.csv
            fprintf(fp, "%s,%s,%s\n", username, hashed_password, role);
            fclose(fp);

            snprintf(response, sizeof(response), "%s berhasil register", username);
        }
    }

    write(client_socket, response, strlen(response));
}

void hashPassword(const char *password, char *hashed_password)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context != NULL)
    {
        if (EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
            if (EVP_DigestUpdate(context, password, strlen(password)))
            {
                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    for (unsigned int i = 0; i < lengthOfHash; i++)
                    {
                        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
                    }
                    hashed_password[lengthOfHash * 2] = '\0';
                }
            }
        }
        EVP_MD_CTX_free(context);
    }
}

void loginUser(char *username, char *password, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s berhasil login", username);
    write(client_socket, response, strlen(response));
}

void listChannels(int client_socket)
{
    DIR *d;
    struct dirent *dir;
    char channels[BUFFER_SIZE][256];
    int count = 0;

    d = opendir("DiscorIT");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                snprintf(channels[count], sizeof(channels[count]), "%s", dir->d_name);
                count++;
            }
        }
        closedir(d);
    }

    for (int i = 0; i < count - 1; i++)
    {
        for (int j = i + 1; j < count; j++)
        {
            if (strcmp(channels[i], channels[j]) > 0)
            {
                char temp[256];
                strcpy(temp, channels[i]);
                strcpy(channels[i], channels[j]);
                strcpy(channels[j], temp);
            }
        }
    }

    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < count; i++)
    {
        strcat(response, channels[i]);
        if (i < count - 1)
        {
            strcat(response, " ");
        }
    }

    send(client_socket, response, strlen(response), 0);
}

void listRooms(int client_socket)
{
    DIR *d, *sub_dir;
    struct dirent *dir, *sub_dirent;
    char path[BUFFER_SIZE];
    char *channels[MAX_CHANNELS];
    char *rooms[MAX_CHANNELS][MAX_ROOMS];
    int channel_count = 0;
    int room_counts[MAX_CHANNELS] = {0};

    d = opendir("DiscorIT");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                channels[channel_count] = strdup(dir->d_name);
                snprintf(path, sizeof(path), "DiscorIT/%s", dir->d_name);

                sub_dir = opendir(path);
                if (sub_dir)
                {
                    while ((sub_dirent = readdir(sub_dir)) != NULL)
                    {
                        if (sub_dirent->d_type == DT_DIR && strcmp(sub_dirent->d_name, ".") != 0 && strcmp(sub_dirent->d_name, "..") != 0)
                        {
                            rooms[channel_count][room_counts[channel_count]] = strdup(sub_dirent->d_name);
                            room_counts[channel_count]++;
                        }
                    }
                    closedir(sub_dir);
                }
                channel_count++;
            }
        }
        closedir(d);
    }

    for (int i = 0; i < channel_count - 1; i++)
    {
        for (int j = i + 1; j < channel_count; j++)
        {
            if (strcmp(channels[i], channels[j]) > 0)
            {
                char *temp = channels[i];
                channels[i] = channels[j];
                channels[j] = temp;

                int temp_count = room_counts[i];
                room_counts[i] = room_counts[j];
                room_counts[j] = temp_count;

                char *temp_rooms[MAX_ROOMS];
                memcpy(temp_rooms, rooms[i], sizeof(temp_rooms));
                memcpy(rooms[i], rooms[j], sizeof(temp_rooms));
                memcpy(rooms[j], temp_rooms, sizeof(temp_rooms));
            }
        }
    }

    for (int i = 0; i < channel_count; i++)
    {
        for (int j = 0; j < room_counts[i] - 1; j++)
        {
            for (int k = j + 1; k < room_counts[i]; k++)
            {
                if (strcmp(rooms[i][j], rooms[i][k]) > 0)
                {
                    char *temp = rooms[i][j];
                    rooms[i][j] = rooms[i][k];
                    rooms[i][k] = temp;
                }
            }
        }
    }

    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < channel_count; i++)
    {
        strcat(response, channels[i]);
        strcat(response, " : ");
        for (int j = 0; j < room_counts[i]; j++)
        {
            strcat(response, rooms[i][j]);
            if (j < room_counts[i] - 1)
            {
                strcat(response, " ");
            }
        }
        strcat(response, "\n");
    }

    if (response[strlen(response) - 1] == '\n')
    {
        response[strlen(response) - 1] = '\0';
    }

    send(client_socket, response, strlen(response), 0);

    for (int i = 0; i < channel_count; i++)
    {
        free(channels[i]);
        for (int j = 0; j < room_counts[i]; j++)
        {
            free(rooms[i][j]);
        }
    }
}

void listUser(int client_socket)
{
    FILE *file;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *usernames[MAX_USERS];
    int user_count = 0;

    file = fopen("DiscorIT/users.csv", "r");
    if (file == NULL)
    {
        perror("Could not open users.csv");
        return;
    }

    while ((read = getline(&line, &len, file)) != -1)
    {
        // Extract the username from the line
        char *token = strtok(line, ",");
        if (token != NULL)
        {
            usernames[user_count] = strdup(token);
            user_count++;
        }
    }
    fclose(file);
    if (line)
        free(line);

    // Sort usernames alphabetically
    for (int i = 0; i < user_count - 1; i++)
    {
        for (int j = i + 1; j < user_count; j++)
        {
            if (strcmp(usernames[i], usernames[j]) > 0)
            {
                char *temp = usernames[i];
                usernames[i] = usernames[j];
                usernames[j] = temp;
            }
        }
    }

    // Build the response string
    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < user_count; i++)
    {
        strcat(response, usernames[i]);
        if (i < user_count - 1)
        {
            strcat(response, " ");
        }
        free(usernames[i]);
    }

    // Send the response to the client
    send(client_socket, response, strlen(response), 0);
}

void joinChannel(char *username, char *channel, int client_socket)
{
    char response[BUFFER_SIZE];
    char *role = get_user_role(username);

    if (role == NULL)
    {
        snprintf(response, sizeof(response), "Gagal mendapatkan role user");
        send(client_socket, response, strlen(response), 0);
        return;
    }

    if (strcmp(role, "USER") == 0)
    {
        // Request key for USER role
        snprintf(response, sizeof(response), "Key: ");
        send(client_socket, response, strlen(response), 0);

        char key[BUFFER_SIZE];
        int bytes_received = recv(client_socket, key, sizeof(key) - 1, 0);
        if (bytes_received > 0)
        {
            key[bytes_received] = '\0';
            snprintf(response, sizeof(response), "[%s/%s]", username, channel);
            send(client_socket, response, strlen(response), 0);
        }
        else
        {
            snprintf(response, sizeof(response), "Key tidak valid");
            send(client_socket, response, strlen(response), 0);
        }
    }
    else
    {
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        send(client_socket, response, strlen(response), 0);
    }
    send(client_socket, response, strlen(response), 0);
}

void joinRoom(char *username, char *channel, char *room, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s joined %s in %s", username, room, channel);
    write(client_socket, response, strlen(response));
}

void chatMessages(char *username, char *channel, char *room, char *message, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "[%s] %s: %s", channel, username, message);
    write(client_socket, response, strlen(response));
}

void seeChat(char *username, char *channel, char *room, int client_socket)
{
    char response[BUFFER_SIZE] = "Previous chats in room";
    write(client_socket, response, strlen(response));
}

void editChat(char *username, char *channel, char *room, int id, char *new_message, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Message %d edited to: %s", id, new_message);
    write(client_socket, response, strlen(response));
}

void deleteChat(char *username, char *channel, char *room, int id, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Message %d deleted", id);
    write(client_socket, response, strlen(response));
}

void errorResponse(char *message, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Error: %s", message);
    write(client_socket, response, strlen(response));
}

void sigint_handler(int sig)
{
    printf("\nServer shutting down...\n");
    exit(EXIT_SUCCESS);
}

void createChannel(char *channel, char *key, int client_socket, char *user)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s created by %s", channel, user);
    write(client_socket, response, strlen(response));
}

int findUser(char *username)
{
    return 1;
}

void editChannel(char *old_name, char *new_name, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s edited to %s", old_name, new_name);
    write(client_socket, response, strlen(response));
}

void deleteChannel(char *channel_name, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s deleted", channel_name);
    write(client_socket, response, strlen(response));
}
```
</details>

### Discorit.c
<details>

<summary>Code discorit.c</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8082
#define BUFFER_SIZE 1024

void registerUser(int server_socket, char *username, char *password);
void loginUser(int server_socket, char *username, char *password);
void joinChannel(int server_socket, char *username, char *channel);
void handleCommand(int server_socket, char *command);
int sendCommand(int server_socket, char *command);
int receiveResponse(int server_socket, char *buffer, size_t buffer_size);

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

void joinChannel(int server_socket, char *username, char *channel)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "JOIN %s %s", username, channel);
    sendCommand(server_socket, buffer);

    if (receiveResponse(server_socket, buffer, sizeof(buffer)))
    {
        printf("%s\n", buffer);
    }
}

void handleCommand(int server_socket, char *command)
{
    char buffer[BUFFER_SIZE];

    write(server_socket, command, strlen(command));

    int bytes_read = read(server_socket, buffer, sizeof(buffer));
    if (bytes_read > 0)
    {
        buffer[bytes_read] = '\0';
        printf("%s\n", buffer);
    }
}

int sendCommand(int server_socket, char *command)
{
    send(server_socket, command, strlen(command), 0);
    return 1;
}

int receiveResponse(int server_socket, char *buffer, size_t buffer_size)
{
    int bytes_received = recv(server_socket, buffer, buffer_size - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        return 1;
    }
    else if (bytes_received == 0)
    {
        printf("Server closed the connection.\n");
    }
    else
    {
        perror("Error receiving response");
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 5 || (strcmp(argv[1], "REGISTER") != 0 && strcmp(argv[1], "LOGIN") != 0) || strcmp(argv[3], "-p") != 0)
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "For REGISTER: %s REGISTER username -p password\n", argv[0]);
        fprintf(stderr, "For LOGIN: %s LOGIN username -p password\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *command = argv[1];
    char *username = argv[2];
    char *password = argv[4];

    int server_socket;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (strcmp(command, "REGISTER") == 0)
    {
        registerUser(server_socket, username, password);
    }
    else if (strcmp(command, "LOGIN") == 0)
    {
        loginUser(server_socket, username, password);
    }
    else
    {
        fprintf(stderr, "Invalid command\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    close(server_socket);
    return 0;
}
```
</details>

### Monitor.c
<details>

<summary>Code monitor.c</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8082
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    char channel[BUFFER_SIZE];
    char room[BUFFER_SIZE];
} monitor_args_t;

void* monitor_chat(void *args);

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <USERNAME> -channel <CHANNEL_NAME> -room <ROOM_NAME>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

char *username = argv[1];
    char *channel = argv[3];
    char *room = argv[5];

    int server_socket;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    char login_command[BUFFER_SIZE];
    snprintf(login_command, sizeof(login_command), "LOGIN %s", username);
    send(server_socket, login_command, strlen(login_command), 0);
char response[BUFFER_SIZE];
    int bytes_received = recv(server_socket, response, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        response[bytes_received] = '\0';
        printf("%s\n", response);
    }

    monitor_args_t monitor_args;
    monitor_args.socket = server_socket;
    strcpy(monitor_args.channel, channel);
    strcpy(monitor_args.room, room);

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, monitor_chat, &monitor_args);
    pthread_join(monitor_thread, NULL);

    close(server_socket);
    return 0;
}

void* monitor_chat(void *args) {
    monitor_args_t *monitor_args = (monitor_args_t *)args;
    int server_socket = monitor_args->socket;
    char *channel = monitor_args->channel;
    char *room = monitor_args->room;

    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command), "SEE CHAT %s %s", channel, room);
send(server_socket, command, strlen(command), 0);

    char buffer[BUFFER_SIZE];
    while (1) {
        int bytes_received = recv(server_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("%s\n", buffer);
        } else {
            break;
        }
    }

    return NULL;
}

```
</details>

----

#### > Penjelasan
### *`Server.c`*
### Header dan Makro
Bagian ini mengimpor berbagai header yang diperlukan dan mendefinisikan beberapa makro untuk ukuran buffer dan panjang maksimum untuk berbagai elemen seperti nama file, nama pengguna, dan kata sandi.
<details>

<summary>Detail Code</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8082
#define BUFFER_SIZE 1024

#define MAX_FILENAME_LEN 100
#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define MAX_CHANNELS 10
#define MAX_ROOMS 10
#define MAX_USERS 100
#define SALT_LEN 16
```

</details>


### Struktur Client
`client_t` adalah struktur yang menyimpan informasi mengenai client, termasuk socket dan alamat mereka.
<details>

<summary>Detail Code</summary>

```c
typedef struct
{
    int socket;
    struct sockaddr_in address;
} client_t;
```

</details>


### Deklarasi Fungsi
Deklarasi berbagai fungsi yang akan digunakan dalam server, seperti `register_user`, `login_user`, `list_channels`, dan lain-lain.
<details>

<summary>Detail Code</summary>

```c
void handleClient(client_t *client);
void *clientHandler(void *arg);
int user_exists(const char *username);
char *get_user_role(const char *username);
void registerUser(char *username, char *password, int client_socket);
void hashPassword(const char *password, char *hashed_password);
void loginUser(char *username, char *password, int client_socket);
void listChannels(int client_socket);
void listRooms(int client_socket);
void listUser(int client_socket);
void joinChannel(char *username, char *channel, int client_socket);
void joinRoom(char *username, char *channel, char *room, int client_socket);
void chatMessages(char *username, char *channel, char *room, char *message, int client_socket);
void seeChat(char *username, char *channel, char *room, int client_socket);
void editChat(char *username, char *channel, char *room, int id, char *new_message, int client_socket);
void deleteChat(char *username, char *channel, char *room, int id, int client_socket);
void errorResponse(char *message, int client_socket);
void sigint_handler(int sig);
void createChannel(char *channel, char *key, int client_socket, char *user);
int findUser(char *username);
void editChannel(char *old_name, char *new_name, int client_socket);
void deleteChannel(char *channel_name, int client_socket);
```

</details>

### Fungsi Utama
Fungsi `main` adalah inti dari server. Ini mencakup pembuatan socket, pengaturan opsi socket, binding, listening, dan loop untuk menerima koneksi klien. Setiap koneksi klien yang diterima akan ditangani oleh thread baru yang menjalankan fungsi `client_handler`.
<details>

<summary>Detail Code</summary>

```c
int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    pthread_t tid;

    signal(SIGINT, sigint_handler);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while (1)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0)
        {
            perror("Accept failed");
            continue;
        }

        client_t *client = malloc(sizeof(client_t));
        client->socket = client_socket;
        client->address = client_addr;

        if (pthread_create(&tid, NULL, clientHandler, (void *)client) != 0)
        {
            perror("Thread creation failed");
            close(client_socket);
            free(client);
        }
    }

    close(server_socket);
    return 0;
}
```

</details>


### Handler untuk Client
Fungsi `clientHandler` ini memungkinkan server untuk melakukan operasi seperti registrasi, login, bergabung dengan channel, membuat channel, mengedit channel, menghapus channel, dan memberikan daftar channel, room, atau pengguna yang tersedia.
<details>

<summary>Detail Code</summary>

```c
void *clientHandler(void *arg)
{
    client_t *client = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(client->socket, buffer, BUFFER_SIZE - 1)) > 0)
    {
        buffer[bytes_read] = '\0';

        char *entity = strtok(NULL, " ");
        char *command = strtok(buffer, " ");
        if (strcmp(command, "REGISTER") == 0)
        {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            registerUser(username, password, client->socket);
        }
        else if (strcmp(command, "LOGIN") == 0)
        {
            char *username = strtok(NULL, " ");
            char *password = strtok(NULL, " ");
            loginUser(username, password, client->socket);
        }
        else if (strcmp(command, "JOIN") == 0)
        {
            char *username = strtok(NULL, " ");
            char *channel = strtok(NULL, " ");

            if (strcmp(entity, "CHANNEL") == 0)
            {
                joinChannel(username, channel, client->socket);
            }
            else if (username == NULL || channel == NULL)
            {
                errorResponse("Invalid JOIN command format", client->socket);
            }
            else
            {
                printf("Handling JOIN for user: %s to channel: %s\n", username, channel); // Log
            }
        }

        else if (strcmp(command, "LIST") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                listChannels(client->socket);
            }
            else if (strcmp(entity, "ROOM") == 0)
            {
                listRooms(client->socket);
            }
            else if (strcmp(entity, "USER") == 0)
            {
                listUser(client->socket);
            }
        }
        else if (strcmp(command, "CREATE") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *channel = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                char *username = strtok(NULL, " ");
                createChannel(channel, key, client->socket, username);
            }
        }
        else if (strcmp(command, "EDIT") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *old_name = strtok(NULL, " ");
                char *new_name = strtok(NULL, " ");
                editChannel(old_name, new_name, client->socket);
            }
        }
        else if (strcmp(command, "DEL") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                char *channel_name = strtok(NULL, " ");
                deleteChannel(channel_name, client->socket);
            }
        }
        else
        {
            errorResponse("Invalid command", client->socket);
        }
    }

    free(client);
    close(client->socket);
    return NULL;
}
```

</details>

### Fungsi `user_exists`
Fungsi ini digunakan untuk memeriksa apakah suatu pengguna (user) sudah ada dalam file CSV tertentu. Fungsi ini bernama user_exists dan menerima satu argumen berupa pointer ke string (const char *username) yang merepresentasikan nama pengguna yang ingin diperiksa.
<details>

<summary>Detail Code</summary>

```c
int user_exists(const char *username)
{
    FILE *fp = fopen("DiscorIT/users.csv", "r");
    if (fp == NULL)
    {
        perror("Failed to open users.csv");
        return 0;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp))
    {
        char *token = strtok(line, ",");
        if (token != NULL && strcmp(token, username) == 0)
        {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}
```

</details>

### Fungsi `get_user_role`
Fungsi ini mencari dan mengembalikan peran (role) dari pengguna yang sesuai dengan nama pengguna yang diberikan dari file `users.csv`.
<details>

<summary>Detail Code</summary>

```c
char *get_user_role(const char *username)
{
    static char role[10];
    FILE *fp = fopen("DiscorIT/users.csv", "r");
    if (fp == NULL)
    {
        perror("Failed to open users.csv");
        return NULL;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), fp))
    {
        char *file_username = strtok(line, ",");
        char *file_role = strtok(NULL, "\n");

        if (strcmp(file_username, username) == 0)
        {
            strcpy(role, file_role);
            fclose(fp);
            return role;
        }
    }
    fclose(fp);
    return NULL;
}
```

</details>

### Fungsi `registerUser`
Fungsi ini adalah mendaftarkan pengguna baru dengan menambahkan informasi pengguna ke file CSV.
- Parameter: `username`, `password`, dan `client_socket`.
- Proses:
  - Membuka file users.csv.
  - Mengecek apakah username sudah ada dalam file.
  - Jika tidak ada, menambahkan username dengan password dan ID baru.
- Keluaran: Mengirimkan pesan ke client socket apakah register berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void registerUser(char *username, char *password, int client_socket)
{
    char response[BUFFER_SIZE];

    if (user_exists(username))
    {
        snprintf(response, sizeof(response), "%s sudah terdaftar", username);
    }
    else
    {
        FILE *fp = fopen("DiscorIT/users.csv", "a+");
        if (fp == NULL)
        {
            perror("Failed to open users.csv");
            snprintf(response, sizeof(response), "Gagal membuka file users.csv");
        }
        else
        {
            fseek(fp, 0, SEEK_END);
            long file_size = ftell(fp);
            const char *role = (file_size == 0) ? "ROOT" : "USER";

            // Hash the password
            char hashed_password[65]; // 64 characters + null terminator
            hashPassword(password, hashed_password);

            // Append new user to users.csv
            fprintf(fp, "%s,%s,%s\n", username, hashed_password, role);
            fclose(fp);

            snprintf(response, sizeof(response), "%s berhasil register", username);
        }
    }

    write(client_socket, response, strlen(response));
}

void hashPassword(const char *password, char *hashed_password)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context != NULL)
    {
        if (EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
            if (EVP_DigestUpdate(context, password, strlen(password)))
            {
                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    for (unsigned int i = 0; i < lengthOfHash; i++)
                    {
                        sprintf(hashed_password + (i * 2), "%02x", hash[i]);
                    }
                    hashed_password[lengthOfHash * 2] = '\0';
                }
            }
        }
        EVP_MD_CTX_free(context);
    }
}
```

</details>

### Fungsi `loginUser`
Fungsi ini memverifikasi username dan password pengguna dengan mencocokkannya dengan data dalam file CSV.
- Parameter: `username`, `password`, dan `client_socket`.
- Proses:
  - Membuka file `users.csv`.
  - Mencari kecocokan antara username dan password.
- Keluaran: Mengirimkan pesan ke client socket apakah login berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void loginUser(char *username, char *password, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s berhasil login", username);
    write(client_socket, response, strlen(response));
}

void listChannels(int client_socket)
{
    DIR *d;
    struct dirent *dir;
    char channels[BUFFER_SIZE][256];
    int count = 0;

    d = opendir("DiscorIT");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                snprintf(channels[count], sizeof(channels[count]), "%s", dir->d_name);
                count++;
            }
        }
        closedir(d);
    }

    for (int i = 0; i < count - 1; i++)
    {
        for (int j = i + 1; j < count; j++)
        {
            if (strcmp(channels[i], channels[j]) > 0)
            {
                char temp[256];
                strcpy(temp, channels[i]);
                strcpy(channels[i], channels[j]);
                strcpy(channels[j], temp);
            }
        }
    }

    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < count; i++)
    {
        strcat(response, channels[i]);
        if (i < count - 1)
        {
            strcat(response, " ");
        }
    }

    send(client_socket, response, strlen(response), 0);
}
```

</details>

### Fungsi `createChannel`
Fungsi ini membuat saluran channel baru, menambahkan entri ke `channels.csv`, dan membuat direktori serta file yang diperlukan untuk saluran tersebut.
- Parameter: `channel`, `key`, `client_socket`, dan `user`.
- Proses:
  - Memeriksa apakah saluran sudah ada.
  - Membuat direktori untuk saluran.
  - Menambahkan informasi saluran ke `channels.csv`.
  - Membuat direktori admin dan file `auth.csv`.
- Keluaran: Mengirimkan pesan ke client socket apakah pembuatan saluran channel berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void createChannel(char *channel, char *key, int client_socket, char *user)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s created by %s", channel, user);
    write(client_socket, response, strlen(response));
}

int findUser(char *username)
{
    return 1;
}
```

</details>

### Fungsi `editChannel`
Fungsi ini mengganti nama saluran channel jika saluran channel lama ada dan nama baru belum digunakan.
- Parameter: `old_name`, `new_name`, dan `client_socket`.
- Proses:
  - Memeriksa apakah saluran lama ada.
  - Memeriksa apakah nama baru belum digunakan.
  - Mengganti nama saluran channel.
- Keluaran: Mengirimkan pesan ke client socket apakah penggantian nama berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void editChannel(char *old_name, char *new_name, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s edited to %s", old_name, new_name);
    write(client_socket, response, strlen(response));
}
```

</details>

### Fungsi `deleteChannel`
Fungsi ini menghapus saluran jika saluran channel yang ada ngin dihapus.
- Parameter: `channel_name` dan `client_socket`.
- Proses:
  - Memeriksa apakah saluran channel ada.
  - Menghapus saluran channel.
- Keluaran: Mengirimkan pesan ke client socket apakah penghapusan saluran channel berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void deleteChannel(char *channel_name, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Channel %s deleted", channel_name);
    write(client_socket, response, strlen(response));
}
```

</details>

### Fungsi `listChannels`
Fungsi ini mencetak daftar saluran channel yang ada.
- Parameter: `client_socket`.
- Proses:
  - Membuka file `channels.csv`.
  - Membaca dan mencetak daftar saluran channel.
- Keluaran: Mengirimkan daftar saluran channel ke client socket.
<details>

<summary>Detail Code</summary>

```c
void listChannels(int client_socket)
{
    DIR *d;
    struct dirent *dir;
    char channels[BUFFER_SIZE][256];
    int count = 0;

    d = opendir("DiscorIT");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                snprintf(channels[count], sizeof(channels[count]), "%s", dir->d_name);
                count++;
            }
        }
        closedir(d);
    }

    for (int i = 0; i < count - 1; i++)
    {
        for (int j = i + 1; j < count; j++)
        {
            if (strcmp(channels[i], channels[j]) > 0)
            {
                char temp[256];
                strcpy(temp, channels[i]);
                strcpy(channels[i], channels[j]);
                strcpy(channels[j], temp);
            }
        }
    }

    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < count; i++)
    {
        strcat(response, channels[i]);
        if (i < count - 1)
        {
            strcat(response, " ");
        }
    }

    send(client_socket, response, strlen(response), 0);
}
```

</details>

### Fungsi `joinChannel`
Fungsi ini memungkinkan pengguna untuk bergabung ke saluran channel yang ada.
- Parameter: `username`, `channel`, dan `client_socket`.
- Proses:
  - Memeriksa apakah saluran ada di `channels.csv`.
  - Jika ada, menambahkan pengguna ke `auth.csv` dalam direktori saluran.
- Keluaran: Mengirimkan pesan ke client socket apakah bergabung ke saluran berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void joinChannel(char *username, char *channel, int client_socket)
{
    char response[BUFFER_SIZE];
    char *role = get_user_role(username);

    if (role == NULL)
    {
        snprintf(response, sizeof(response), "Gagal mendapatkan role user");
        send(client_socket, response, strlen(response), 0);
        return;
    }

    if (strcmp(role, "USER") == 0)
    {
        // Request key for USER role
        snprintf(response, sizeof(response), "Key: ");
        send(client_socket, response, strlen(response), 0);

        char key[BUFFER_SIZE];
        int bytes_received = recv(client_socket, key, sizeof(key) - 1, 0);
        if (bytes_received > 0)
        {
            key[bytes_received] = '\0';
            snprintf(response, sizeof(response), "[%s/%s]", username, channel);
            send(client_socket, response, strlen(response), 0);
        }
        else
        {
            snprintf(response, sizeof(response), "Key tidak valid");
            send(client_socket, response, strlen(response), 0);
        }
    }
    else
    {
        snprintf(response, sizeof(response), "[%s/%s]", username, channel);
        send(client_socket, response, strlen(response), 0);
    }
    send(client_socket, response, strlen(response), 0);
}

```

</details>

### Fungsi `listRooms`
Fungsi ini mencetak daftar room yang ada.
- Parameter: `channel` dan `client_socket`.
- Proses:
  - Membuka file `channels.csv`.
  - Membaca dan mencetak daftar room.
- Keluaran: Mengirimkan daftar room ke client socket.
<details>

<summary>Detail Code</summary>

```c
void listRooms(int client_socket)
{
    DIR *d, *sub_dir;
    struct dirent *dir, *sub_dirent;
    char path[BUFFER_SIZE];
    char *channels[MAX_CHANNELS];
    char *rooms[MAX_CHANNELS][MAX_ROOMS];
    int channel_count = 0;
    int room_counts[MAX_CHANNELS] = {0};

    d = opendir("DiscorIT");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
            {
                channels[channel_count] = strdup(dir->d_name);
                snprintf(path, sizeof(path), "DiscorIT/%s", dir->d_name);

                sub_dir = opendir(path);
                if (sub_dir)
                {
                    while ((sub_dirent = readdir(sub_dir)) != NULL)
                    {
                        if (sub_dirent->d_type == DT_DIR && strcmp(sub_dirent->d_name, ".") != 0 && strcmp(sub_dirent->d_name, "..") != 0)
                        {
                            rooms[channel_count][room_counts[channel_count]] = strdup(sub_dirent->d_name);
                            room_counts[channel_count]++;
                        }
                    }
                    closedir(sub_dir);
                }
                channel_count++;
            }
        }
        closedir(d);
    }

    for (int i = 0; i < channel_count - 1; i++)
    {
        for (int j = i + 1; j < channel_count; j++)
        {
            if (strcmp(channels[i], channels[j]) > 0)
            {
                char *temp = channels[i];
                channels[i] = channels[j];
                channels[j] = temp;

                int temp_count = room_counts[i];
                room_counts[i] = room_counts[j];
                room_counts[j] = temp_count;

                char *temp_rooms[MAX_ROOMS];
                memcpy(temp_rooms, rooms[i], sizeof(temp_rooms));
                memcpy(rooms[i], rooms[j], sizeof(temp_rooms));
                memcpy(rooms[j], temp_rooms, sizeof(temp_rooms));
            }
        }
    }

    for (int i = 0; i < channel_count; i++)
    {
        for (int j = 0; j < room_counts[i] - 1; j++)
        {
            for (int k = j + 1; k < room_counts[i]; k++)
            {
                if (strcmp(rooms[i][j], rooms[i][k]) > 0)
                {
                    char *temp = rooms[i][j];
                    rooms[i][j] = rooms[i][k];
                    rooms[i][k] = temp;
                }
            }
        }
    }

    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < channel_count; i++)
    {
        strcat(response, channels[i]);
        strcat(response, " : ");
        for (int j = 0; j < room_counts[i]; j++)
        {
            strcat(response, rooms[i][j]);
            if (j < room_counts[i] - 1)
            {
                strcat(response, " ");
            }
        }
        strcat(response, "\n");
    }

    if (response[strlen(response) - 1] == '\n')
    {
        response[strlen(response) - 1] = '\0';
    }

    send(client_socket, response, strlen(response), 0);

    for (int i = 0; i < channel_count; i++)
    {
        free(channels[i]);
        for (int j = 0; j < room_counts[i]; j++)
        {
            free(rooms[i][j]);
        }
    }
}
```

</details>

### Fungsi `joinRoom`
Fungsi ini memverifikasi username dan password pengguna dengan mencocokkannya dengan data dalam file CSV.
- Parameter: `username`, `password`, dan `client_socket`.
- Proses:
  - Membuka file `users.csv`.
  - Mencari kecocokan antara username dan password.
- Keluaran: Mengirimkan pesan ke client socket apakah login berhasil atau gagal.
<details>

<summary>Detail Code</summary>

```c
void joinRoom(char *username, char *channel, char *room, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s joined %s in %s", username, room, channel);
    write(client_socket, response, strlen(response));
}
```

</details>

### Fungsi `listUser`
Fungsi ini mencetak daftar pengguna dalam saluran tertentu.
- Parameter: `client_socket`.
- Proses:
  - Membuka file `auth.csv` dalam direktori saluran.
  - Membaca dan mencetak daftar pengguna.
- Keluaran: Mengirimkan daftar pengguna dalam saluran ke client socket.
<details>

<summary>Detail Code</summary>

```c
void listUser(int client_socket)
{
    FILE *file;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *usernames[MAX_USERS];
    int user_count = 0;

    file = fopen("DiscorIT/users.csv", "r");
    if (file == NULL)
    {
        perror("Could not open users.csv");
        return;
    }

    while ((read = getline(&line, &len, file)) != -1)
    {
        // Extract the username from the line
        char *token = strtok(line, ",");
        if (token != NULL)
        {
            usernames[user_count] = strdup(token);
            user_count++;
        }
    }
    fclose(file);
    if (line)
        free(line);

    // Sort usernames alphabetically
    for (int i = 0; i < user_count - 1; i++)
    {
        for (int j = i + 1; j < user_count; j++)
        {
            if (strcmp(usernames[i], usernames[j]) > 0)
            {
                char *temp = usernames[i];
                usernames[i] = usernames[j];
                usernames[j] = temp;
            }
        }
    }

    // Build the response string
    char response[BUFFER_SIZE] = "";
    for (int i = 0; i < user_count; i++)
    {
        strcat(response, usernames[i]);
        if (i < user_count - 1)
        {
            strcat(response, " ");
        }
        free(usernames[i]);
    }

    // Send the response to the client
    send(client_socket, response, strlen(response), 0);
}
```

</details>

### *`Discorit.c`*
### Header dan Makro
Bagian ini mengimpor berbagai header yang diperlukan dan mendefinisikan beberapa makro untuk alamat IP server, port server, dan ukuran buffer.
<details>

<summary>Detail Code</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8082
#define BUFFER_SIZE 1024
```

</details>

### Deklarasi Fungsi
Deklarasi berbagai fungsi yang akan digunakan dalam client, seperti `registerUser`, `loginUser`, `joinChannel`, `handleCommand`, `sendCommand`, dan `receiveResponse`.
<details>

<summary>Detail Code</summary>

```c
void registerUser(int server_socket, char *username, char *password);
void loginUser(int server_socket, char *username, char *password);
void joinChannel(int server_socket, char *username, char *channel);
void handleCommand(int server_socket, char *command);
int sendCommand(int server_socket, char *command);
int receiveResponse(int server_socket, char *buffer, size_t buffer_size);
```

</details>

### Fungsi `registerUser`
Fungsi ini mengirimkan perintah REGISTER ke server dengan username dan password yang diberikan, kemudian menerima respons dari server.
```bin
./program REGISTER username -p password
```
<details>

<summary>Detail Code</summary>

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


### Fungsi `loginUser`
Fungsi ini mengirimkan perintah LOGIN ke server dengan username dan password yang diberikan, kemudian menerima respons dari server.
```bin
./program LOGIN username -p password
```

<details>

<summary>Detail Code</summary>

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

### Fungsi `joinChannel`
Fungsi ini mengirimkan perintah JOIN ke server dengan channel yang diberikan, kemudian menerima respons dari server.
```bin
JOIN channel
```
<details>

<summary>Detail Code</summary>

```c
void joinChannel(int server_socket, char *username, char *channel)
{
    char buffer[BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "JOIN %s %s", username, channel);
    sendCommand(server_socket, buffer);

    if (receiveResponse(server_socket, buffer, sizeof(buffer)))
    {
        printf("%s\n", buffer);
    }
}
```

</details>

### Fungsi `handleCommand`
Fungsi handleCommand digunakan untuk mengirim perintah dari klien ke server dan menampilkan respons yang diterima dari server.
- Mengirim perintah ke server melalui socket.
- Membaca respons dari server ke dalam buffer.
- Menampilkan respons yang diterima.
<details>

<summary>Detail Code</summary>

```c
void handleCommand(int server_socket, char *command)
{
    char buffer[BUFFER_SIZE];

    write(server_socket, command, strlen(command));

    int bytes_read = read(server_socket, buffer, sizeof(buffer));
    if (bytes_read > 0)
    {
        buffer[bytes_read] = '\0';
        printf("%s\n", buffer);
    }
}
```

</details>

### Fungsi `sendCommand`
Fungsi ini mengirimkan perintah ke server melalui socket.
<details>

<summary>Detail Code</summary>

```c
int sendCommand(int server_socket, char *command)
{
    send(server_socket, command, strlen(command), 0);
    return 1;
}
```

</details>

### Fungsi `receiveResponse`
Fungsi ini bertanggung jawab untuk menerima respons dari server melalui socket, menyimpannya dalam buffer, dan jika server menutup koneksi, fungsi ini mengakhiri program.
<details>

<summary>Detail Code</summary>

```c
int receiveResponse(int server_socket, char *buffer, size_t buffer_size)
{
    int bytes_received = recv(server_socket, buffer, buffer_size - 1, 0);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        return 1;
    }
    else if (bytes_received == 0)
    {
        printf("Server closed the connection.\n");
    }
    else
    {
        perror("Error receiving response");
    }
    return 0;
}
```

</details>

### Fungsi `main`
Fungsi main memeriksa argumen yang diberikan saat menjalankan program. Kemudian membuat socket, menghubungkan ke server, dan memanggil fungsi yang sesuai (`registerUser` atau `loginUser`) berdasarkan perintah yang diberikan.
```bin
./program REGISTER username -p password
```
```bin
./program LOGIN username -p password
```
<details>

<summary>Detail Code</summary>

```c
int main(int argc, char *argv[])
{
    if (argc < 5 || (strcmp(argv[1], "REGISTER") != 0 && strcmp(argv[1], "LOGIN") != 0) || strcmp(argv[3], "-p") != 0)
    {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "For REGISTER: %s REGISTER username -p password\n", argv[0]);
        fprintf(stderr, "For LOGIN: %s LOGIN username -p password\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *command = argv[1];
    char *username = argv[2];
    char *password = argv[4];

    int server_socket;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (strcmp(command, "REGISTER") == 0)
    {
        registerUser(server_socket, username, password);
    }
    else if (strcmp(command, "LOGIN") == 0)
    {
        loginUser(server_socket, username, password);
    }
    else
    {
        fprintf(stderr, "Invalid command\n");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    close(server_socket);
    return 0;
}
```

</details>

### *`Monitor.c`*
### Fungsi Utama *`main`*
1. Parsing Argumen:
- Program ini membutuhkan argumen dari baris perintah untuk `USERNAME`, `-channel`, dan `-room`. Jika kurang dari enam argumen diberikan (`<USERNAME> -channel <CHANNEL_NAME> -room <ROOM_NAME>`), program akan mencetak pesan penggunaan dan keluar.

2. Pembuatan dan Koneksi Socket:
- Membuat sebuah soket TCP (`server_socket`) dengan menggunakan `socket(AF_INET, SOCK_STREAM, 0)`.
- Mendefinisikan alamat server (`server_addr`) menggunakan `SERVER_IP` dan `SERVER_PORT`, kemudian mencoba untuk terhubung ke server dengan `connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr))`.

3. Login Pengguna:
- Membuat perintah login (`LOGIN <USERNAME>`) dan mengirimkannya ke server menggunakan send(`server_socket, login_command, strlen(login_command), 0`).
- Menerima respons dari server yang menunjukkan keberhasilan atau kegagalan percobaan login.

4. Persiapan Pemantauan Obrolan:
- Menginisialisasi struktur `monitor_args_t` (`monitor_args`) untuk meneruskan argumen ke dalam thread pemantauan (`monitor_chat`).
- Menyalin `CHANNEL_NAME` dan `ROOM_NAME` ke dalam `monitor_args`.
- Membuat sebuah thread (`monitor_thread`) menggunakan `pthread_create` untuk memulai pemantauan obrolan.

5. Manajemen Thread:
- Menunggu hingga thread pemantauan selesai menggunakan `pthread_join`.
- Menutup `server_socket` setelah thread pemantauan selesai.

### Thread Pemantauan *`monitor_chat`*
1. Penanganan Argumen:
- Mengubah parameter `void *args` kembali menjadi `monitor_args_t *` untuk mengakses soket dan parameter obrolan (`channel` dan `room`).

2. Pemantauan Obrolan:
- Membuat sebuah perintah (`SEE CHAT <CHANNEL_NAME> <ROOM_NAME>`) dan mengirimkannya ke server menggunakan send(`server_socket, command, strlen(command), 0`).
- Memasuki loop untuk terus-menerus menerima pesan obrolan dari server menggunakan recv.
- Mencetak pesan yang diterima ke konsol sampai koneksi ditutup atau terjadi kesalahan.
<details>

<summary>Detail Code Monitor.c</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8082
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    char channel[BUFFER_SIZE];
    char room[BUFFER_SIZE];
} monitor_args_t;

void* monitor_chat(void *args);

int main(int argc, char *argv[]) {
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <USERNAME> -channel <CHANNEL_NAME> -room <ROOM_NAME>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

char *username = argv[1];
    char *channel = argv[3];
    char *room = argv[5];

    int server_socket;
    struct sockaddr_in server_addr;

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Define server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // Connect to the server
    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Log in to the server
    char login_command[BUFFER_SIZE];
    snprintf(login_command, sizeof(login_command), "LOGIN %s", username);
    send(server_socket, login_command, strlen(login_command), 0);
char response[BUFFER_SIZE];
    int bytes_received = recv(server_socket, response, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        response[bytes_received] = '\0';
        printf("%s\n", response);
    }

    // Start monitoring the chat
    monitor_args_t monitor_args;
    monitor_args.socket = server_socket;
    strcpy(monitor_args.channel, channel);
    strcpy(monitor_args.room, room);

    pthread_t monitor_thread;
    pthread_create(&monitor_thread, NULL, monitor_chat, &monitor_args);
    pthread_join(monitor_thread, NULL);

    close(server_socket);
    return 0;
}

void* monitor_chat(void *args) {
    monitor_args_t *monitor_args = (monitor_args_t *)args;
    int server_socket = monitor_args->socket;
    char *channel = monitor_args->channel;
    char *room = monitor_args->room;

    char command[BUFFER_SIZE];
    snprintf(command, sizeof(command), "SEE CHAT %s %s", channel, room);
send(server_socket, command, strlen(command), 0);

    char buffer[BUFFER_SIZE];
    while (1) {
        int bytes_received = recv(server_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("%s\n", buffer);
        } else {
            break;
        }
    }

    return NULL;
}

```

</details>

----

#### > Dokumentasi
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/745ab882-1616-43b9-815f-a4e9b4d9b64d>
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/589bf0dd-15bf-4efd-a059-c27bf13e10d8>
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/90337a2b-5e85-4390-810b-084867cdce22>
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/30123db8-0626-458e-bfb5-ac7aa0ffc0ee>
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/3d2127e6-ca34-4019-bda8-afadb9b3aafc>
<img width="1710" alt="image" src=https://github.com/HazwanAdhikara/Sisop-FP-2024-MH-IT13/assets/150534107/1e6392db-b743-4ec4-b4a6-159b7dde7b1a>

----

#### > Revisi
