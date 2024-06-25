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
                    else if (strcmp(buffer, "exit") == 0)
                    {
                        break;
                    }
                    else if (strcmp(buffer, "LIST CHANNEL") == 0)
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
