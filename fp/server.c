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

#define PORT 8082
#define BUFFER_SIZE 1024

#define MAX_FILENAME_LEN 100
#define MAX_USERNAME_LEN 50
#define MAX_PASSWORD_LEN 50
#define SALT_LEN 16

typedef struct
{
    int socket;
    struct sockaddr_in address;
} client_t;

void handleClient(client_t *client);
void *clientHandler(void *arg);
void registerUser(char *username, char *password, int client_socket);
void hashPassword(const char *password, char *hashed_password);
void loginUser(char *username, char *password, int client_socket);
void listChannels(int client_socket);
void joinChannel(char *username, char *channel, char *key, int client_socket);
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
        else if (strcmp(command, "LIST") == 0)
        {
            char *entity = strtok(NULL, " ");
            if (strcmp(entity, "CHANNEL") == 0)
            {
                listChannels(client->socket);
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
    char response[BUFFER_SIZE] = "CHANNEL1,CHANNEL2";
    write(client_socket, response, strlen(response));
}

void joinChannel(char *username, char *channel, char *key, int client_socket)
{
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s joined %s", username, channel);
    write(client_socket, response, strlen(response));
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
